# IPC

All CLI-to-bridge command traffic uses `BridgeClient` in [client.rs](client.rs).
Typed adapters construct arguments; unsupported adapters can use
`send_command(command, args)` directly. [protocol.rs](protocol.rs) defines the
wire structs; [client/transport.rs](client/transport.rs) owns transport and its
tests. Raw TCP elsewhere is only a liveness probe.

## Connection and timeout boundaries

Each request uses a fresh localhost TCP connection for one newline-terminated
JSON request and response. Socket handlers run independently of the serialized
Ghidra program lane; see [Java execution ownership](../ghidra/scripts/ghidracli/README.md).

Retry transient connection failures with backoff only **before sending**; replaying
a sent mutation could duplicate it. Read waits include time in the program queue.
The write timeout is 30s; configurable read/connect/long-operation budgets are in
[the runtime reference](../../docs/runtime.md). Decompiler execution timeout stays
in its command adapter because it is a Ghidra parameter, not a socket budget.
EOF without a reply is an error; read timeouts exit 75 without cancelling the job.
Shutdown uses the caller's remaining total deadline for connect, write, and read;
it must not fall back to an independent generic socket timeout. The lifecycle
caller also budgets lock acquisition and process exit, preserves the typed
timeout error, and retains live discovery on failure.
`BridgeClient` sends `shutdown_wait`, advertised by `bridge_info.durable_shutdown`,
to receive final save failures as errors. Legacy `shutdown` only acknowledges
drain acceptance and cannot confirm saving; clients must not use it as a fallback.
The new request waits outside the bounded program queue and leaves controls
available. Save failure retains the JVM and reopens the queue for recovery.

## Wire format

```json
{"command":"list_functions","args":{"limit":100}}
{"status":"success","data":{"functions":[]},"message":null}
```

Request `command` is required; optional `args` is omitted when `None`.
Response `data` and `message` are optional. The CLI unwraps the response and
chooses its output format; the bridge always sends compact JSON.

`bridge_info.auto_save: true` advertises saving before successful program
responses. `program_save` retries pending saves without restarting. A save failure
returns `error` with `detail.save_failed: true`, `saved: false`, and the original
`command_response`; do not replay the edit. Errors with retained, saved changes
include `detail.partial_changes_saved: true`.

| Response status | Client result |
|---|---|
| `success` | `data`, or `{}` if absent |
| `error` | Error with `message` and available structured detail |
| `shutdown` | `{"status":"shutdown"}` |
| Other | `data`, or `{}` if absent |
