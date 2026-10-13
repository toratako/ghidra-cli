import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import java.lang.reflect.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Supplier;

public class CheckRuntimeSnapshotPublication extends GhidraScript {
  static Method method(Class<?> type, String name, Class<?>... arguments) throws Exception {
    Method method = type.getDeclaredMethod(name, arguments);
    method.setAccessible(true);
    return method;
  }

  static JsonObject response(Object reply) throws Exception {
    Field completion = reply.getClass().getDeclaredField("completion");
    completion.setAccessible(true);
    return (JsonObject) ((Supplier<?>) ((CompletableFuture<?>) completion.get(reply)).get()).get();
  }

  static void check(boolean condition, String message) {
    if (!condition) throw new IllegalStateException(message);
  }

  public void run() throws Exception {
    String prefix = String.join(".", "ghidracli", "runtime") + ".";
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
    AtomicBoolean changed = new AtomicBoolean();
    CountDownLatch readingPath = new CountDownLatch(1);
    CountDownLatch releasePath = new CountDownLatch(1);
    DomainFile file =
        (DomainFile)
            Proxy.newProxyInstance(
                DomainFile.class.getClassLoader(),
                new Class<?>[] {DomainFile.class},
                (proxy, operation, args) -> {
                  if (operation.getName().equals("getName"))
                    return changed.get() ? "next" : "previous";
                  if (operation.getName().equals("getPathname")) {
                    if (!changed.get()) return "/previous";
                    readingPath.countDown();
                    check(
                        releasePath.await(5, TimeUnit.SECONDS),
                        "Snapshot path read was not released");
                    return "/next";
                  }
                  throw new UnsupportedOperationException(operation.getName());
                });
    Program selected =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, operation, args) -> {
                  switch (operation.getName()) {
                    case "getDomainFile":
                      return file;
                    case "addConsumer":
                      return true;
                    default:
                      throw new UnsupportedOperationException(operation.getName());
                  }
                });
    Class<?> accessType =
        loader.loadClass(String.join(".", "ghidracli", "session", "ScriptAccess"));
    Object access =
        Proxy.newProxyInstance(
            loader,
            new Class<?>[] {accessType},
            (proxy, operation, args) -> {
              switch (operation.getName()) {
                case "program":
                  return selected;
                case "state":
                  return null;
                default:
                  throw new UnsupportedOperationException(operation.getName());
              }
            });
    Class<?> sessionType =
        loader.loadClass(String.join(".", "ghidracli", "session", "ProgramSession"));
    Object session = sessionType.getConstructor(accessType).newInstance(access);
    Class<?> schedulerType = loader.loadClass(prefix + "JobScheduler");
    Class<?> commandsType = loader.loadClass(prefix + "CommandDispatcher");
    Constructor<?> constructor = schedulerType.getDeclaredConstructor(sessionType, commandsType);
    constructor.setAccessible(true);
    Object scheduler = constructor.newInstance(session, null);
    method(schedulerType, "start").invoke(scheduler);
    Method request = method(schedulerType, "handleRequest", String.class);
    Method refresh = method(schedulerType, "refreshBridgeSnapshot");
    AtomicReference<Throwable> failure = new AtomicReference<>();
    changed.set(true);
    Thread publisher =
        new Thread(
            () -> {
              try {
                refresh.invoke(scheduler);
              } catch (Throwable error) {
                failure.set(error);
              }
            });
    publisher.start();
    JsonObject during;
    try {
      check(readingPath.await(2, TimeUnit.SECONDS), "Snapshot refresh never read the program path");
      during =
          response(request.invoke(scheduler, "{\"command\":\"bridge_info\"}"))
              .getAsJsonObject("data");
    } finally {
      releasePath.countDown();
      publisher.join(5000);
    }
    check(
        !publisher.isAlive() && failure.get() == null,
        "Snapshot refresh did not complete: " + failure.get());
    check(
        "previous".equals(during.get("current_program").getAsString())
            && "/previous".equals(during.get("current_program_path").getAsString()),
        "Control observed a partially published program identity: " + during);
    JsonObject after =
        response(request.invoke(scheduler, "{\"command\":\"bridge_info\"}"))
            .getAsJsonObject("data");
    check(
        "next".equals(after.get("current_program").getAsString())
            && "/next".equals(after.get("current_program_path").getAsString()),
        "Completed refresh was not published: " + after);
    println("runtime publishes coherent program snapshots");
  }
}
