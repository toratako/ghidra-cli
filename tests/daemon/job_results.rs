use super::{start_daemon, TEST_PROGRAM};
use crate::common::{ensure_test_project, test_project};
use ghidra_cli::ipc::{client::BridgeClient, protocol::BridgeCommandError};
use serde_json::{json, Value};
use serial_test::serial;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

fn send_without_reading(port: u16, request: &Value) {
    let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    writeln!(socket, "{request}").unwrap();
}

fn completed(client: &BridgeClient, id: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = client.job_status(Some(id)).unwrap();
        if status["job"]["finished_at_ms"].is_number() {
            return status["job"].clone();
        }
        assert!(Instant::now() < deadline, "Job did not finish: {status}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[serial]
fn disconnected_edits_retain_results_and_errors_without_reexecution() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let address = crate::common::helpers::get_fixture_function(&client, "add_numbers").address;
    let id = uuid::Uuid::new_v4().to_string();
    let request = json!({"command": "comment_set", "job_id": id,
        "args": {"address": address, "text": "recovered edit", "comment_type": "EOL"}});
    send_without_reading(harness.port(), &request);
    assert_eq!(completed(&client, &id)["state"], "complete");
    let result = client.job_result(&id).unwrap();
    assert_eq!(result["id"], id);
    assert_eq!(result["command"], "comment_set");
    assert_eq!(result["result"]["state"], "available");
    assert_eq!(result["response"]["status"], "success");
    assert_eq!(result["response"]["job_id"], id);

    // Retrieving an old response must not replay its mutation or inspect current state.
    client
        .comment_set(&address, "later edit", Some("EOL"))
        .unwrap();
    assert_eq!(client.job_result(&id).unwrap(), result);
    let mut duplicate = TcpStream::connect(("127.0.0.1", harness.port())).unwrap();
    duplicate
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(duplicate, "{request}").unwrap();
    let mut line = String::new();
    BufReader::new(duplicate).read_line(&mut line).unwrap();
    let rejection: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(rejection["status"], "error");
    assert!(rejection["message"]
        .as_str()
        .unwrap()
        .contains("already exists"));
    assert!(client.comment_get(&address).unwrap()["comments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|comment| comment["text"] == "later edit"));
    assert_eq!(client.job_result(&id).unwrap(), result);

    let failed_id = uuid::Uuid::new_v4().to_string();
    send_without_reading(
        harness.port(),
        &json!({"command": "comment_set", "job_id": failed_id,
        "args": {"address": address, "text": "must not land", "comment_type": "invalid"}}),
    );
    assert_eq!(completed(&client, &failed_id)["state"], "failed");
    let failure = client.job_result(&failed_id).unwrap();
    assert_eq!(failure["response"]["status"], "error");
    assert_eq!(failure["response"]["detail"]["rolled_back"], true);
    assert!(failure["response"]["message"]
        .as_str()
        .unwrap()
        .contains("Invalid comment type"));
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args([
            "--json",
            "--project",
            test_project(),
            "job",
            "result",
            &failed_id,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "A failed operation's result is still retrievable: {output:?}"
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        crate::json_output::from_slice::<Value>(&output.stdout).unwrap(),
        failure
    );

    drop(harness);
    let restarted = start_daemon();
    let error = restarted.client().unwrap().job_result(&id).unwrap_err();
    assert_eq!(
        error.downcast_ref::<BridgeCommandError>().unwrap().detail["result_state"],
        "unknown"
    );
}

#[test]
#[serial]
fn queued_result_is_pending_and_cancelled_response_can_be_recovered() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    let client = harness.client().unwrap();
    let worker = harness.client().unwrap();
    let script = std::thread::spawn(move || {
        worker.script_run_source(
            r#"
import ghidra.app.script.GhidraScript;
public class HoldJobResults extends GhidraScript {
    public void run() throws Exception {
        monitor.setMessage("holding-for-result-recovery");
        long deadline = System.currentTimeMillis() + 30000;
        while (System.currentTimeMillis() < deadline) {
            monitor.checkCancelled();
            Thread.sleep(10);
        }
        throw new IllegalStateException("Test did not cancel the script");
    }
}
"#,
            &[],
            &[],
            false,
        )
    });
    let deadline = Instant::now() + Duration::from_secs(25);
    let active_id = loop {
        let status = client.status().unwrap();
        if status["active_job"]["progress_message"] == "holding-for-result-recovery" {
            break status["active_job"]["id"].as_str().unwrap().to_owned();
        }
        assert!(!script.is_finished());
        assert!(Instant::now() < deadline, "{status}");
        std::thread::sleep(Duration::from_millis(10));
    };
    let id = uuid::Uuid::new_v4().to_string();
    send_without_reading(harness.port(), &json!({"command": "stats", "job_id": id}));
    loop {
        if client.job_status(Some(&id)).unwrap()["found"] == true {
            break;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = assert_cmd::cargo::cargo_bin_cmd!("ghidra-cli")
        .args(["--json", "--project", test_project(), "job", "result", &id])
        .timeout(Duration::from_secs(5))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(75));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["status"], "pending");
    assert_eq!(error["detail"]["result_state"], "pending");
    assert_eq!(error["detail"]["job"]["state"], "queued");
    assert!(error["detail"].get("outcome_unknown").is_none());
    client.cancel_job(Some(&id)).unwrap();
    let cancelled = client.job_result(&id).unwrap();
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(
        cancelled["response"]["message"],
        "Cancelled before execution"
    );
    assert!(client.ping().unwrap());
    client.cancel_job(Some(&active_id)).unwrap();
    let error = script.join().unwrap().unwrap_err();
    let active = client.job_result(&active_id).unwrap();
    assert_eq!(active["response"]["message"], error.to_string());
    if let Some(error) = error.downcast_ref::<BridgeCommandError>() {
        assert_eq!(active["response"]["detail"], error.detail);
    }
    assert_eq!(active["state"], "cancelled");
}

#[test]
#[serial]
fn result_store_bounds_utf8_bytes_expiry_and_eviction_without_real_time_waits() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    harness.client().unwrap().script_run_source(r#"
import ghidra.app.script.GhidraScript;
import com.google.gson.JsonObject;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class CheckJobResultStore extends GhidraScript {
    static void check(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
    static Method method(Class<?> type, String name, Class<?>... args) throws Exception {
        Method method = type.getDeclaredMethod(name, args);
        method.setAccessible(true);
        return method;
    }
    static Field field(Class<?> type, String name) throws Exception {
        Field field = type.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }
    public void run() throws Exception {
        ClassLoader loader = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getName().equals("ghidracli.script.ScriptCommands"))
                .findFirst().orElseThrow()).getClassLoader();
        Class<?> type = loader.loadClass("ghidracli.runtime.JobResultStore");
        Class<?> entry = loader.loadClass("ghidracli.runtime.JobResultStore$Entry");
        Constructor<?> constructor = type.getDeclaredConstructor(long.class, int.class, int.class);
        constructor.setAccessible(true);
        Object store = constructor.newInstance(10L, 50, 32);
        Method snapshot = method(type, "snapshot", JsonObject.class);
        Method retain = method(type, "retain", byte[].class, long.class);
        Method expire = method(type, "expire", long.class);
        Method forget = method(type, "forget", entry);
        Field body = field(entry, "body"), state = field(entry, "state");
        JsonObject response = new JsonObject();
        response.addProperty("value", "éééé");
        byte[] encoded = (byte[]) snapshot.invoke(store, response);
        check(Arrays.equals(encoded, response.toString().getBytes(StandardCharsets.UTF_8)), "UTF-8 snapshot");
        Object first = retain.invoke(store, encoded, 100L);
        byte[] held = (byte[]) body.get(first);
        response.addProperty("value", "changed");
        check(new String(held, StandardCharsets.UTF_8).contains("éééé"), "snapshot changed");
        Object second = retain.invoke(store, encoded, 101L);
        Object third = retain.invoke(store, encoded, 102L);
        check("evicted".equals(state.get(first)) && body.get(first) == null, "byte eviction");
        check(Arrays.equals(held, encoded), "in-flight reader lost its snapshot");
        expire.invoke(store, 110L);
        check("available".equals(state.get(second)), "expired early");
        expire.invoke(store, 111L);
        check("expired".equals(state.get(second)) && body.get(second) == null, "expiry boundary");
        forget.invoke(store, third);
        check(field(type, "retainedBytes").getLong(store) == 0, "history eviction leaked bytes");
        response.addProperty("value", "é".repeat(40));
        byte[] oversized = (byte[]) snapshot.invoke(store, response);
        check(oversized == null, "per-result UTF-8 limit");
        Object missing = retain.invoke(store, oversized, 120L);
        check("too_large".equals(state.get(missing)), "oversized reason");
        check(field(type, "retainedBytes").getLong(store) == 0, "oversized result retained");
        // History eviction must remove the lookup and release its retained body too.
        Class<?> schedulerType = loader.loadClass("ghidracli.runtime.JobScheduler");
        Class<?> recordType = loader.loadClass("ghidracli.runtime.JobScheduler$JobRecord");
        Constructor<?> schedulerConstructor = schedulerType.getDeclaredConstructors()[0];
        schedulerConstructor.setAccessible(true);
        Object scheduler = schedulerConstructor.newInstance(null, null);
        Constructor<?> recordConstructor = recordType.getDeclaredConstructor(String.class, String.class);
        recordConstructor.setAccessible(true);
        Method complete = method(schedulerType, "retainCompletedJob", recordType, byte[].class);
        java.util.Map jobs = (java.util.Map) field(schedulerType, "jobs").get(scheduler);
        int maxJobs = field(type, "MAX_JOBS").getInt(null);
        Object oldest = null;
        for (int i = 0; i <= maxJobs; i++) {
            Object record = recordConstructor.newInstance(new java.util.UUID(0, i).toString(), "stats");
            field(recordType, "finishedAt").setLong(record, System.currentTimeMillis());
            jobs.put(field(recordType, "id").get(record), record);
            complete.invoke(scheduler, record, encoded);
            if (i == 0) oldest = record;
        }
        check(jobs.size() == maxJobs, "history count limit");
        check(!jobs.containsKey(new java.util.UUID(0, 0).toString()), "old history remains addressable");
        check(body.get(field(recordType, "result").get(oldest)) == null, "history retains evicted bytes");
        println("job result limits checked");
    }
}

"#, &[], &[], false).unwrap();
}

#[test]
#[serial]
fn deferred_result_reads_do_not_occupy_control_connection_threads() {
    require_ghidra!();
    ensure_test_project(test_project(), TEST_PROGRAM);
    let harness = start_daemon();
    harness.client().unwrap().script_run_source(r#"
import ghidra.app.script.GhidraScript;
import com.google.gson.JsonObject;
import java.io.*;
import java.net.*;
import java.lang.reflect.*;
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
        ClassLoader loader = StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE)
            .walk(frames -> frames.map(StackWalker.StackFrame::getDeclaringClass)
                .filter(type -> type.getName().equals("ghidracli.script.ScriptCommands"))
                .findFirst().orElseThrow()).getClassLoader();
        Class<?> reply = loader.loadClass("ghidracli.runtime.BridgeReply");
        Method immediate = method(reply, "immediate", JsonObject.class);
        Method deferred = method(reply, "deferred", Supplier.class);
        Class<?> type = loader.loadClass("ghidracli.runtime.BridgeServer");
        Constructor<?> constructor = type.getDeclaredConstructor(Function.class, Runnable.class,
            BooleanSupplier.class, Consumer.class);
        constructor.setAccessible(true);
        AtomicInteger accepted = new AtomicInteger();
        CountDownLatch release = new CountDownLatch(1);
        JsonObject response = new JsonObject();
        response.addProperty("status", "success");
        Supplier<JsonObject> slowResult = () -> {
            try {
                if (!release.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("Release timed out");
            } catch (InterruptedException e) { throw new IllegalStateException(e); }
            return response;
        };
        Function<String, Object> requests = line -> {
            try {
                if (line.equals("slow-result")) {
                    accepted.incrementAndGet();
                    return deferred.invoke(null, slowResult);
                }
                return immediate.invoke(null, response);
            } catch (Exception e) { throw new IllegalStateException(e); }
        };
        Object server = constructor.newInstance(requests, (Runnable) () -> {},
            (BooleanSupplier) () -> false, (Consumer<String>) message -> {});
        List<Socket> waiting = new ArrayList<>();
        try {
            method(type, "start").invoke(server);
            int port = (Integer) method(type, "port").invoke(server);
            for (int i = 0; i < 40; i++) {
                Socket socket = new Socket("127.0.0.1", port);
                waiting.add(socket);
                new PrintWriter(socket.getOutputStream(), true).println("slow-result");
            }
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (accepted.get() != 40) {
                if (System.nanoTime() >= deadline) throw new IllegalStateException("Results occupied the control pool");
                Thread.sleep(5);
            }
            try (Socket ping = new Socket("127.0.0.1", port)) {
                ping.setSoTimeout(2000);
                new PrintWriter(ping.getOutputStream(), true).println("ping");
                String line = new BufferedReader(new InputStreamReader(ping.getInputStream())).readLine();
                if (line == null || !line.contains("success")) throw new IllegalStateException("Control did not reply");
            }
        } finally {
            release.countDown();
            for (Socket socket : waiting) socket.close();
            method(type, "close").invoke(server);
        }
        println("deferred results leave controls responsive");
    }
}
"#, &[], &[], false).unwrap();
}
