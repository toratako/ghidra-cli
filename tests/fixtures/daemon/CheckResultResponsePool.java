import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import java.io.*;
import java.lang.reflect.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.*;

public class CheckResultResponsePool extends GhidraScript {
  static Method method(Class<?> type, String name, Class<?>... args) throws Exception {
    Method method = type.getDeclaredMethod(name, args);
    method.setAccessible(true);
    return method;
  }

  public void run() throws Exception {
    ClassLoader loader =
        StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(
                frames ->
                    frames
                        .map(StackWalker.StackFrame::getDeclaringClass)
                        .filter(type -> type.getName().equals("ghidracli.script.ScriptCommands"))
                        .findFirst()
                        .orElseThrow())
            .getClassLoader();
    Class<?> reply = loader.loadClass("ghidracli.runtime.BridgeReply");
    Method immediate = method(reply, "immediate", JsonObject.class);
    Method deferred = method(reply, "deferred", Supplier.class);
    Class<?> type = loader.loadClass("ghidracli.runtime.BridgeServer");
    Constructor<?> constructor =
        type.getDeclaredConstructor(
            Function.class, Runnable.class, BooleanSupplier.class, Consumer.class);
    constructor.setAccessible(true);
    AtomicInteger accepted = new AtomicInteger();
    CountDownLatch release = new CountDownLatch(1);
    JsonObject response = new JsonObject();
    response.addProperty("status", "success");
    Supplier<JsonObject> slowResult =
        () -> {
          try {
            if (!release.await(10, TimeUnit.SECONDS))
              throw new IllegalStateException("Release timed out");
          } catch (InterruptedException e) {
            throw new IllegalStateException(e);
          }
          return response;
        };
    Function<String, Object> requests =
        line -> {
          try {
            if (line.equals("slow-result")) {
              accepted.incrementAndGet();
              return deferred.invoke(null, slowResult);
            }
            return immediate.invoke(null, response);
          } catch (Exception e) {
            throw new IllegalStateException(e);
          }
        };
    Object server =
        constructor.newInstance(
            requests,
            (Runnable) () -> {},
            (BooleanSupplier) () -> false,
            (Consumer<String>) message -> {});
    List<Socket> waiting = new ArrayList<>();
    try {
      method(type, "start").invoke(server);
      int port = (Integer) method(type, "port").invoke(server);
      for (int i = 0; i < 40; i++) {
        Socket socket = new Socket("127.0.0.1", port);
        waiting.add(socket);
        // The raw callback retains CR; println would send CRLF on Windows.
        socket.getOutputStream().write("slow-result\n".getBytes(StandardCharsets.UTF_8));
      }
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      while (accepted.get() != 40) {
        if (System.nanoTime() >= deadline)
          throw new IllegalStateException("Results occupied the control pool");
        Thread.sleep(5);
      }
      try (Socket ping = new Socket("127.0.0.1", port)) {
        ping.setSoTimeout(2000);
        ping.getOutputStream().write("ping\n".getBytes(StandardCharsets.UTF_8));
        String line = new BufferedReader(new InputStreamReader(ping.getInputStream())).readLine();
        if (line == null || !line.contains("success"))
          throw new IllegalStateException("Control did not reply");
      }
    } finally {
      release.countDown();
      for (Socket socket : waiting) socket.close();
      method(type, "close").invoke(server);
    }
    println("deferred results leave controls responsive");
  }
}
