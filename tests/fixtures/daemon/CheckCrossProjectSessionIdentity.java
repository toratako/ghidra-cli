import ghidra.app.script.GhidraScript;
import ghidra.base.project.GhidraProject;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import java.lang.reflect.Proxy;
import java.nio.file.Files;

public class CheckCrossProjectSessionIdentity extends GhidraScript {
  private static void check(boolean condition, String message) {
    if (!condition) throw new IllegalStateException(message);
  }

  public void run() throws Exception {
    var root = state.getProject().getProjectData().getRootFolder();
    var localFolder = root.createFolder(getScriptArgs()[0]);
    DomainFile localFile = currentProgram.getDomainFile().copyTo(localFolder, monitor);
    var directory = Files.createTempDirectory("ghidra-cli-cross-project-session-");
    GhidraProject external = GhidraProject.createProject(directory.toString(), "external", true);
    Object owner = new Object();
    Program remote = null;
    Object session = null;
    Class<?> sessionClass = null;
    try {
      var remoteFolder =
          external.getProjectData().getRootFolder().createFolder(localFolder.getName());
      DomainFile remoteFile = currentProgram.getDomainFile().copyTo(remoteFolder, monitor);
      check(
          localFile.getPathname().equals(remoteFile.getPathname()),
          "Fixture paths must collide across projects");
      check(!localFile.equals(remoteFile), "Fixture files must belong to different projects");
      remote = (Program) remoteFile.getDomainObject(owner, true, false, monitor);
      Program[] selected = {remote};
      Class<?> bridgeCaller =
          StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
              .walk(
                  frames ->
                      frames
                          .map(StackWalker.StackFrame::getDeclaringClass)
                          .filter(type -> type.getSimpleName().equals("ScriptCommands"))
                          .findFirst()
                          .orElseThrow());
      ClassLoader loader = bridgeCaller.getClassLoader();
      String prefix =
          bridgeCaller
              .getPackageName()
              .substring(0, bridgeCaller.getPackageName().lastIndexOf('.') + 1);
      Class<?> accessClass = loader.loadClass(prefix + "session.ScriptAccess");
      Object access =
          Proxy.newProxyInstance(
              loader,
              new Class<?>[] {accessClass},
              (proxy, method, args) -> {
                switch (method.getName()) {
                  case "program":
                    return selected[0];
                  case "setProgram":
                    selected[0] = (Program) args[0];
                    return null;
                  case "state":
                    return state;
                  case "monitor":
                    return monitor;
                  case "logError":
                    printerr((String) args[0]);
                    return null;
                  default:
                    throw new UnsupportedOperationException(method.getName());
                }
              });
      sessionClass = loader.loadClass(prefix + "session.ProgramSession");
      session = sessionClass.getConstructor(accessClass).newInstance(access);
      check(
          !(boolean)
              sessionClass.getMethod("isCurrent", DomainFile.class).invoke(session, localFile),
          "A same-path Program from another project was mistaken for the local target");
      sessionClass.getMethod("open", DomainFile.class).invoke(session, localFile);
      check(
          selected[0].getDomainFile().equals(localFile),
          "Opening the local target retained the other project's Program");
      check(!remote.isClosed(), "Switching released another consumer's Program");
      check(
          (boolean)
              sessionClass.getMethod("isCurrent", DomainFile.class).invoke(session, localFile),
          "The selected local target was not recognized");
      println("cross-project-session-ok");
    } finally {
      try {
        if (session != null) sessionClass.getMethod("closeProgram").invoke(session);
      } finally {
        if (remote != null) remote.release(owner);
        external.close();
        Files.delete(directory);
        localFile.delete();
        localFolder.delete();
      }
    }
  }
}
