use super::{start_daemon, TEST_PROGRAM};
use crate::common::{self, ensure_test_project, test_project};
use predicates::prelude::*;
use serial_test::serial;

#[test]
#[serial]
fn test_daemon_start() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "status"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_status() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "status"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success()
        .stdout(predicate::str::contains("running"));

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_ping() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "ping"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_lifecycle() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let _harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "status"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success()
        .stdout(predicate::str::contains("running"));

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "ping"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "stop"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();
}

#[test]
#[serial]
fn test_daemon_stop() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "stop"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "status"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success()
        .stdout(predicate::str::contains("No bridge running"));

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_restart() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    // Use run_cli_with_timeout to avoid Windows pipe handle inheritance.
    // `ghidra-cli bridge restart` stops the old bridge and starts a new JVM. With piped
    // stdout/stderr, the new JVM inherits pipe handles, blocking forever.
    let ghidra_bin = assert_cmd::cargo::cargo_bin!("ghidra-cli");
    let status = common::run_cli_with_timeout(
        ghidra_bin,
        &[
            "bridge",
            "restart",
            "--project",
            test_project(),
            "--program",
            TEST_PROGRAM,
        ],
        std::time::Duration::from_secs(300),
    )
    .expect("Failed to run restart");

    assert!(status.success(), "Restart failed with status: {status}");

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "stop"])
        .arg("--project")
        .arg(test_project())
        .assert()
        .success();

    drop(harness);
}

#[test]
#[serial]
fn test_daemon_start_when_running() {
    require_ghidra!();

    ensure_test_project(test_project(), TEST_PROGRAM);

    let harness = start_daemon();

    assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["bridge", "start"])
        .arg("--project")
        .arg(test_project())
        .arg("--program")
        .arg(TEST_PROGRAM)
        .assert()
        .success()
        .stdout(predicate::str::contains("already running"));

    drop(harness);
}

#[test]
#[serial]
fn shutdown_closes_incomplete_requests_without_waiting_for_socket_read_timeout() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    harness.client().unwrap().script_run_source(r#"
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
"#, &[], &[], false).unwrap();
}
