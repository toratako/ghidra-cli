
import ghidra.app.script.GhidraScript;
import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.*;

public class CheckIdleConnectionShutdown extends GhidraScript {
    static Method method(Class<?> type, String name) throws Exception {
        Method method = type.getDeclaredMethod(name);
        method.setAccessible(true);
        return method;
    }
    public void run() throws Exception {
        ClassLoader loader = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getName().equals(String.join(".", "ghidracli", "script", "ScriptCommands")))
                .findFirst().orElseThrow()).getClassLoader();
        Class<?> type = loader.loadClass(String.join(".", "ghidracli", "runtime", "BridgeServer"));
        Constructor<?> constructor = type.getDeclaredConstructor(Function.class, Runnable.class,
            BooleanSupplier.class, Consumer.class);
        constructor.setAccessible(true);
        Object server = constructor.newInstance((Function<String, Object>) line -> {
            throw new IllegalStateException("An incomplete request reached dispatch");
        }, (Runnable) () -> {}, (BooleanSupplier) () -> false, (Consumer<String>) message -> {});
        Field executorField = type.getDeclaredField("connectionExecutor");
        executorField.setAccessible(true);
        ThreadPoolExecutor executor = (ThreadPoolExecutor) executorField.get(server);
        Method close = method(type, "close");
        List<Socket> clients = new ArrayList<>();
        CountDownLatch closed = new CountDownLatch(1);
        AtomicReference<Throwable> closeFailure = new AtomicReference<>();
        Thread closer = new Thread(() -> {
            try { close.invoke(server); }
            catch (Throwable error) { closeFailure.set(error); }
            finally { closed.countDown(); }
        });
        try {
            method(type, "start").invoke(server);
            int port = (Integer) method(type, "port").invoke(server);
            // Exercise both workers blocked reading and accepted sockets still queued.
            for (int i = 0; i < 40; i++) clients.add(new Socket("127.0.0.1", port));
            clients.get(0).getOutputStream().write("partial request".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            clients.get(0).getOutputStream().flush();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (executor.getActiveCount() + executor.getQueue().size() != clients.size()) {
                if (System.nanoTime() >= deadline) throw new IllegalStateException("Clients were not accepted");
                Thread.sleep(5);
            }
            closer.start();
            if (!closed.await(2, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Shutdown waited for incomplete clients' read timeout");
            }
            if (closeFailure.get() != null) throw new IllegalStateException(closeFailure.get());
            for (Socket client : clients) {
                client.setSoTimeout(1000);
                try {
                    if (client.getInputStream().read() != -1) {
                        throw new IllegalStateException("Incomplete client remained open");
                    }
                } catch (SocketException reset) {
                    // Reset is also a terminal close of an incomplete connection.
                }
            }
        } finally {
            for (Socket client : clients) client.close();
            if (closer.getState() == Thread.State.NEW) closer.start();
            if (!closed.await(5, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Server cleanup did not finish after clients closed");
            }
        }
        println("incomplete connections close promptly");
    }
}
