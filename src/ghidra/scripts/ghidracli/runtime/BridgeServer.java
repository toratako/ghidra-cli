package ghidracli.runtime;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;

import static ghidracli.protocol.JsonProtocol.errorResponse;

final class BridgeServer {
    private static final int MAX_CLIENT_THREADS = 32;
    private static final int MAX_PENDING_CLIENTS = 128;
    private static final int MAX_RESPONSE_THREADS = 16;
    private static final int MAX_PENDING_RESPONSES = 256;
    private final Gson gson = new GsonBuilder().serializeNulls().create();
    private final AtomicLong nextClientThreadId = new AtomicLong(1);
    private final AtomicLong nextResponseThreadId = new AtomicLong(1);
    private final ServerSocket serverSocket;
    private final ExecutorService connectionExecutor;
    private final ExecutorService responseExecutor;
    private final Function<String, BridgeReply> requests;
    private final Runnable shutdown;
    private final BooleanSupplier shutdownRequested;
    private final Consumer<String> errors;
    private final Thread acceptor;
    private final Set<Socket> clients = ConcurrentHashMap.newKeySet();
    private final Set<Socket> readingClients = ConcurrentHashMap.newKeySet();

    BridgeServer(Function<String, BridgeReply> requests, Runnable shutdown,
            BooleanSupplier shutdownRequested, Consumer<String> errors) throws IOException {
        this.requests = requests;
        this.shutdown = shutdown;
        this.shutdownRequested = shutdownRequested;
        this.errors = errors;
        serverSocket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        connectionExecutor = new ThreadPoolExecutor(
            MAX_CLIENT_THREADS,
            MAX_CLIENT_THREADS,
            60L,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(MAX_PENDING_CLIENTS),
            runnable -> {
                Thread thread = new Thread(
                    runnable,
                    "ghidra-cli-client-" + nextClientThreadId.getAndIncrement());
                thread.setDaemon(true);
                return thread;
            },
            new ThreadPoolExecutor.AbortPolicy());

        responseExecutor = new ThreadPoolExecutor(
            4,
            MAX_RESPONSE_THREADS,
            60L,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(MAX_PENDING_RESPONSES),
            runnable -> {
                Thread thread = new Thread(
                    runnable,
                    "ghidra-cli-response-" + nextResponseThreadId.getAndIncrement());
                thread.setDaemon(true);
                return thread;
            },
            new ThreadPoolExecutor.AbortPolicy());

        acceptor = new Thread(this::acceptClients, "ghidra-cli-acceptor");
        acceptor.setDaemon(true);
    }

    int port() { return serverSocket.getLocalPort(); }
    void start() { acceptor.start(); }

    void close() {
        closeServerSocket();
        try {
            acceptor.join(5000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        // Accepted sockets may still be waiting for their request newline.
        // Interrupting an executor worker does not unblock a socket read.
        for (Socket client : readingClients) closeClient(client);
        shutdownExecutor(connectionExecutor);
        shutdownExecutor(responseExecutor);
        for (Socket client : clients) closeClient(client);
    }

    private void shutdownExecutor(ExecutorService executor) {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(30, TimeUnit.SECONDS)) executor.shutdownNow();
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private void acceptClients() {
        try {
            while (!shutdownRequested.getAsBoolean()) {
                Socket client = serverSocket.accept();
                clients.add(client);
                readingClients.add(client);
                try {
                    connectionExecutor.execute(() -> serveClient(client));
                } catch (RejectedExecutionException e) {
                    rejectClient(client, "Bridge has too many concurrent clients; retry shortly");
                }
            }
        } catch (SocketException e) {
            if (!shutdownRequested.getAsBoolean()) {
                errors.accept("Accept error: " + e.getMessage());
                shutdown.run();
            }
        } catch (IOException e) {
            if (!shutdownRequested.getAsBoolean()) {
                errors.accept("Accept error: " + e.getMessage());
                shutdown.run();
            }
        } finally {
            ExecutorService executor = connectionExecutor;
            if (executor != null) {
                executor.shutdown();
            }
        }
    }

    private void serveClient(Socket client) {
        try {
            // The wire protocol is one JSON request per connection. Parse and
            // enqueue here, but never occupy a connection thread while waiting
            // for serialized Ghidra work to finish.
            client.setSoTimeout(30000);
            BufferedReader in = new BufferedReader(
                new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
            String line = in.readLine();
            readingClients.remove(client);
            if (line == null || line.trim().isEmpty()) {
                closeClient(client);
                return;
            }

            BridgeReply reply = requests.apply(line.trim());
            if (!reply.asynchronous) {
                respondAndClose(client, reply.completion.join().get());
                return;
            }

            reply.completion.whenComplete((result, error) -> {
                try {
                    responseExecutor.execute(() -> {
                        JsonObject response;
                        try {
                            if (error != null) throw new IllegalStateException(error);
                            response = result.get();
                        } catch (Exception failure) {
                            response = errorResponse(failure.getMessage());
                        }
                        respondAndClose(client, response);
                    });
                } catch (RejectedExecutionException e) {
                    closeClient(client);
                }
            });
        } catch (IOException e) {
            closeClient(client);
            if (!shutdownRequested.getAsBoolean()) {
                errors.accept("Client error: " + e.getMessage());
            }
        } finally {
            readingClients.remove(client);
        }
    }

    private void respondAndClose(Socket client, JsonObject result) {
        try (
            Socket closeableClient = client;
            PrintWriter out = new PrintWriter(
                new OutputStreamWriter(closeableClient.getOutputStream(), StandardCharsets.UTF_8), true)
        ) {
            out.println(gson.toJson(result));
            out.flush();
        } catch (IOException e) {
            if (!shutdownRequested.getAsBoolean()) {
                errors.accept("Client response error: " + e.getMessage());
            }
        } finally {
            clients.remove(client);
        }
    }

    private void rejectClient(Socket client, String message) {
        try (
            Socket closeableClient = client;
            PrintWriter out = new PrintWriter(
                new OutputStreamWriter(closeableClient.getOutputStream(), StandardCharsets.UTF_8), true)
        ) {
            out.println(gson.toJson(errorResponse(message)));
        } catch (IOException ignored) {
            // The client may already have disconnected.
        } finally {
            clients.remove(client);
            readingClients.remove(client);
        }
    }

    private void closeClient(Socket client) {
        try {
            client.close();
        } catch (IOException ignored) {
            // The client may already have disconnected.
        } finally {
            clients.remove(client);
            readingClients.remove(client);
        }
    }

    void closeServerSocket() {
        ServerSocket socket = serverSocket;
        if (socket != null && !socket.isClosed()) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // Best-effort cleanup during JVM teardown.
            }
        }
    }
}
