# Changelog

## Unreleased

* **`sudp` proxies and visitors.** The handshake is the `stcp` one over a UDP
  socket, but the session belongs to the *visitor* rather than to a user: the
  first datagram opens it, every later datagram from any user rides on it, and
  each one carries the address it came from, which is what routes the answer
  back. That is the Go client's shape too — one visitor connection fed by a
  shared send channel — and the earlier per-user version of this code, which
  dropped a second user's datagram while the first was talking, was wrong.
* **`stcp` proxies and visitors.** A `stcp` proxy publishes nothing; a visitor on
  another client binds a local port and names it, and the handshake is signed with
  the proxy's secret key rather than the auth token — the per-connection crypto is
  keyed on that same secret, so one session uses two keys. `xtcp` visitors are
  skipped with a warning rather than half-run.
* **`udp` proxies.** Each user gets its own local socket, and a reply carries back
  the address the datagram came from so it reaches the right one; idle sockets are
  dropped after 30 seconds and the work connection is heartbeated every 30, both
  matching the Go client.
* **Two Go JSON encodings serde gets wrong by default**, in `msg::go_types`: a
  `[]byte` is base64 rather than an array of numbers, and `net.IP` is text rather
  than a byte array. Both are silent when they are wrong, so both are pinned
  against output captured from `encoding/json`.
* Removing a leaked process when a memory measurement fails: the harness now
  kills the client on every path, so a failed gate does not leave an eight-megabyte
  process holding the fixture ports.

## 0.1.0 — unreleased

First cut. The compatibility claim is testable end to end: a stock Go `frps`
accepts this client's login, and a registered `tcp` proxy carries real bytes from
the port the server published through to a local service and back.

Build and release:

* No C dependency anywhere — the AES-CFB, snappy framing, SHA-1/HMAC/PBKDF2 and
  the yamux multiplexer are all pure Rust — so cross-compiling needs no
  `gcc-arm-linux-*` package and the process carries no crypto library's per-thread
  state.
* `scripts/build-arm.sh` / `scripts/build-arm.ps1` cross-compile to
  `armv7-unknown-linux-{musleabihf,gnueabihf}` and `aarch64-unknown-linux-musl`.
* `.github/workflows/ci.yml`: format, clippy over all targets, unit tests, a
  Windows job, and two jobs that build a real `frps` from source — one runs the
  end-to-end suite, one enforces the memory budget.
* `.github/workflows/release.yml` builds linux x86_64/aarch64/armv7, macOS arm64
  and Windows, and `scripts/release.sh` tags and dispatches it.
* `tests/memory.rs`: resident-set measurement of the shipped binary as its own
  process, against a real `frps`, gated at the stated budgets.

Features:

* frp's application-layer crypto: `PBKDF2-HMAC-SHA1(secret, "frp", 64)` into
  AES-128-CFB with a lazily written 16-byte IV, plus the `hex(md5(secret ‖
  decimal(timestamp)))` signatures used by `privilege_key` and `sign_key`.
* snappy **framed** compression, which is what `useCompression` selects — not
  zstd, and not snappy's block format.
* The 18 frp message types, with Go-compatible JSON (sorted map keys, HTML
  escaping, and `omitempty` semantics including its no-op behaviour on
  struct-valued fields).
* Both control framings: v1 (`type byte ‖ i64 BE length ‖ JSON`, 10240-byte cap)
  and v2 (7-byte magic plus `u16 type ‖ u16 flags ‖ u32 length` frames).
* Reconnect backoff ported from `pkg/util/wait/backoff.go`, fast retries included.
* Proxy naming (`{user}.{name}`) and the config-template range helpers.
* TOML configuration with `Complete()` defaults and validation, plus the legacy
  `[common]` INI format. The format is chosen by content, not by extension.
* `--check-config`: validate a config and print it normalized, then exit.
* `--strict-config` / `--no-strict-config`, with the key surface checked against
  the model by a test so the two cannot drift.
* **Login handshake against a real `frps`**, with the unconditional AES-128-CFB
  control-connection crypto and the token signature.
* `frpc verify [--server]`: check a config, and with `--server` also log in to
  the configured server and report its version and run id.
* **yamux**, ported from the `fatedier/yamux` v0.2.0 fork, so `transport.tcpMux`
  — which defaults to on — works. Frame layout, flags, window sizes and stream-id
  parity all have tests pinning them against the fork.
* A connector that hides the multiplexed/plain split, so the control session and
  every work connection are opened the same way either way.
* **The control loop**: `NewProxy` registration with the wrapper's
  `new → wait start → running → start error` phases and 3s/20s retry timers,
  `ReqWorkConn → NewWorkConn → StartWorkConn` served per connection in its own
  task, `CloseProxy` on shutdown, and the `Ping`/`Pong` heartbeat.
* **Proxy bridging**: a work connection is joined to `localIP:localPort` with
  16 KiB buffers, with the per-proxy `useEncryption` wrapping applied in frp's
  order.
* The top-level client loop: first-login retry, backoff reconnect that replays the
  previous run id, and graceful shutdown on SIGINT/SIGTERM that deregisters the
  proxies before exiting.
* **The admin API**, on `webServer.port`: `/healthz` (unauthenticated, as the Go
  router has it), `/api/status`, `/api/config` (GET and PUT, written atomically),
  `/api/proxy/{name}/config`, `/api/reload`, `/api/stop` and `/metrics`. Basic
  auth with a constant-time comparison and the Go middleware's 200ms failure
  delay; the error envelope is Go's `{code, msg}`.
* **`frpc reload|status|stop`**, over the same API, with `--api-timeout`
  defaulting to the Go client's 30 seconds. `status` prints the same table per
  proxy type that the Go client prints.
* `tests/real_frps.rs`: asserts a stock `frps` accepts the login with and without
  `tcpMux`, rejects a wrong token, answers a heartbeat on the encrypted control
  connection, accepts a reconnect that replays the previous run id, carries a TCP
  round trip over both transports, carries a UDP round trip with two users at once
  kept apart, carries an `stcp` round trip through a visitor while refusing a
  visitor with the wrong secret key, carries a `sudp` round trip through a visitor
  and serves two `sudp` users one after the other without mixing their answers up,
  survives a proxy whose local service is down,
  and serves the admin API over real HTTP including `stop` and the credential
  check.

## Not yet implemented

* `useCompression` on work connections, and `useEncryption`/`useCompression` on
  `udp` proxies or visitors: a proxy that asks for either has its connections
  refused rather than bridged unwrapped, since the registration told the server
  otherwise.
* The TLS, websocket and KCP transports.
* Proxy types other than `tcp`, `udp`, `stcp` and `sudp`, and the client-side
  plugins.
* The `xtcp` visitor and proxy, which need NAT hole punching.
* `/api/visitor/{name}/config`, `/api/store/*`, and the static dashboard assets.
* Wire protocol v2. `msg.rs` encodes and decodes both framings, but the v2
  `ClientHello` exchange is not implemented, so only v1 is usable end to end —
  which also means the v2-only `binary-v1` UDP packet codec is out of reach.
* The rename-retry strategy is parsed but not applied.
