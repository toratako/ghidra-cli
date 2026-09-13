# IPC

All CLI-to-bridge command traffic uses `BridgeClient` in [client.rs](client.rs).
Typed adapters construct arguments; unsupported adapters can use
`send_command(command, args)` directly. [protocol.rs](protocol.rs) defines the
wire structs; [client/transport.rs](client/transport.rs) owns transport and its
tests. Raw TCP elsewhere is only a liveness probe.

## Connection and timeout boundaries

Each request opens its own localhost TCP connection, writes one newline-terminated
JSON request, and reads one newline-terminated JSON response. There is no
persistent client connection. Socket handlers run independently of the serialized
Ghidra program lane; see [Java execution ownership](../ghidra/scripts/ghidracli/README.md).

Retry transient connection failures with backoff only **before sending**; replaying
a sent mutation could duplicate it. Read waits include time in the program queue.
The write timeout is 30s; configurable read/connect/long-operation budgets are in
[the runtime reference](../../docs/runtime.md). Decompiler execution timeout stays
in its command adapter because it is a Ghidra parameter, not a socket budget.
EOF without a reply is an error. A read timeout has a distinct error/exit status
and does not cancel the running job.

## Wire format

```json
{"command":"list_functions","args":{"limit":100}}
{"status":"success","data":{"functions":[]},"message":null}
```

Request `command` is required; optional `args` is omitted when `None`.
Response `data` and `message` are optional. The CLI unwraps the response and
chooses its output format; the bridge always sends compact JSON.

| Response status | Client result |
|---|---|
| `success` | `data`, or `{}` if absent |
| `error` | Error with `message` and available structured detail |
| `shutdown` | `{"status":"shutdown"}` |
| Other | `data`, or `{}` if absent |
