import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.*;

public class CheckAdmissionSocketOwnership extends GhidraScript {
  static Method method(Class<?> type, String name, Class<?>... args) throws Exception {
    Method method = type.getDeclaredMethod(name, args);
    method.setAccessible(true);
    return method;
  }

  static void send(Socket socket, String request) throws IOException {
    socket.getOutputStream().write((request + "\n").getBytes(StandardCharsets.UTF_8));
    socket.getOutputStream().flush();
  }

  static void requireSuccess(Socket socket) throws IOException {
    socket.setSoTimeout(2000);
    String response =
        new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8))
            .readLine();
    if (response == null || !response.contains("success")) {
      throw new IllegalStateException("Reply was lost: " + response);
    }
  }

  public void run() throws Exception {
    ClassLoader loader =
        StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(
                frames ->
                    frames
                        .map(StackWalker.StackFrame::getDeclaringClass)
                        .filter(
                            type ->
                                type.getName()
                                    .equals(
                                        String.join(".", "ghidracli", "script", "ScriptCommands")))
                        .findFirst()
                        .orElseThrow())
            .getClassLoader();
    Class<?> reply = loader.loadClass(String.join(".", "ghidracli", "runtime", "BridgeReply"));
    Method immediate = method(reply, "immediate", JsonObject.class);
    Method pending = method(reply, "pending", CompletableFuture.class);
    Class<?> type = loader.loadClass(String.join(".", "ghidracli", "runtime", "BridgeServer"));
    Constructor<?> constructor =
        type.getDeclaredConstructor(
            Function.class, Runnable.class, BooleanSupplier.class, Consumer.class);
    constructor.setAccessible(true);
    JsonObject response = new JsonObject();
    response.addProperty("status", "success");
    CompletableFuture<JsonObject> completion = new CompletableFuture<>();
    CountDownLatch pendingAdmitted = new CountDownLatch(1);
    CountDownLatch failed = new CountDownLatch(1);
    AtomicReference<Throwable> failure = new AtomicReference<>();
    Function<String, Object> requests =
        line -> {
          Thread.currentThread()
              .setUncaughtExceptionHandler(
                  (thread, error) -> {
                    failure.set(error);
                    failed.countDown();
                  });
          // Ghidra 11's Gson permits enough nesting to exhaust the parser stack.
          // Inject that fatal exit so the same ownership boundary is tested on newer Gson.
          if (line.equals("failed-admission")) throw new StackOverflowError("Request parse failed");
          try {
            if (line.equals("pending")) {
              pendingAdmitted.countDown();
              return pending.invoke(null, completion);
            }
            return immediate.invoke(null, response);
          } catch (ReflectiveOperationException error) {
            throw new IllegalStateException(error);
          }
        };
    Object server =
        constructor.newInstance(
            requests,
            (Runnable) () -> {},
            (BooleanSupplier) () -> false,
            (Consumer<String>) message -> {});
    try {
      method(type, "start").invoke(server);
      int port = (Integer) method(type, "port").invoke(server);
      try (Socket socket = new Socket("127.0.0.1", port)) {
        socket.setSoTimeout(2000);
        send(socket, "failed-admission");
        try {
          if (socket.getInputStream().read() != -1) {
            throw new IllegalStateException("Failed admission returned a partial reply");
          }
        } catch (SocketException reset) {
          // Reset also releases the failed connection.
        }
      }
      if (!failed.await(2, TimeUnit.SECONDS) || !(failure.get() instanceof StackOverflowError)) {
        throw new IllegalStateException("The fatal admission probe did not run", failure.get());
      }
      try (Socket waiting = new Socket("127.0.0.1", port)) {
        send(waiting, "pending");
        if (!pendingAdmitted.await(2, TimeUnit.SECONDS)) {
          throw new IllegalStateException("Pending request was not admitted");
        }
        waiting.setSoTimeout(200);
        try {
          waiting.getInputStream().read();
          throw new IllegalStateException("Pending reply was closed before completion");
        } catch (SocketTimeoutException expected) {
          // The asynchronous callback still owns the open socket.
        }
        try (Socket control = new Socket("127.0.0.1", port)) {
          send(control, "ping");
          requireSuccess(control);
        }
        completion.complete(response);
        requireSuccess(waiting);
      }
    } finally {
      completion.complete(response);
      method(type, "close").invoke(server);
    }
    println("failed admission releases its socket; pending replies keep ownership");
  }
}
