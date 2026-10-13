# Changelog

## Unreleased

* **A `tls` feature, on by default, so a build can leave TLS out.** It is the
  only thing that removes the `rustls` and `ring` cost, and it takes
  `armv7-unknown-linux-musleabihf` from 2.06 MB to **1.56 MB** — which is where
  it was before TLS existed. `scripts/build-arm.sh --no-tls` and
  `build-arm.ps1 -NoTls` produce it.
* **A build without the feature refuses a TLS config rather than downgrading.**
  That is the whole safety argument for the option: `transport.tls.enable`
  defaults to **true**, so a build that quietly ignored it would turn a size
  optimisation into a plaintext tunnel nobody asked for. The error names both
  ways out — `transport.tls.enable = false`, or a build with the feature — and
  says the same for `transport.protocol = "wss"`, which is a websocket inside
  TLS. The message is a `const` so the test that checks its wording and the
  error that carries it cannot drift apart.
* **Both test suites run in either configuration**, because a build whose other
  half is never exercised is not tested: 246 unit tests and 26 against a real
  `frps` with TLS, 242 and 23 without. The three TLS integration tests are gated
  on the feature; the rest follow the build, so the no-TLS client is driven
  through the whole plain path against a real server rather than merely
  compiled.
* **`--no-tls` is opt-in rather than the ARM default.** Turning it on for every
  ARM user would break `tls.force` servers for them with an error they did not
  ask for, and the flag is one word.

* **The ARM builds stopped throwing away 610 kB in the link step.** Both
  cross-compile scripts and the release workflow overrode the release profile to
  `lto = "off"` and `codegen-units = 16`, with the comment that "full LTO over an
  ARM link can take an unbounded amount of time". Measured, it is 83 seconds
  against 44, and it produces a 2.06 MB `armv7-unknown-linux-musleabihf` binary
  instead of 2.67 MB. That single override cost more than every other size
  decision in the profile combined, and it is gone. A `release-fast` profile
  still exists for iterating.
* **What the TLS stack costs, measured rather than guessed.** About 850 kB of
  the binary — 540 kB of code and 260 kB of read-only tables — and it is not
  recoverable. `opt-level = "s"` is *larger* than `"z"` (2.38 MB against 2.21),
  dropping the `tls12` and `logging` features saves 37 kB, and restricting the
  cipher-suite list to the nine suites a Go server can actually negotiate saves
  nothing at all, because the linker was already dropping the rest. The numbers
  are in both READMEs so the next person does not repeat the search.
* **The `websocket` and `wss` transports.** `frp` uses `golang.org/x/net/websocket`
  rather than the gorilla stack, and the two differ where it counts, so the new
  `proto::websocket` is matched against x/net at the version frp pins: a plain
  `GET /~!frp` upgrade, a base64 nonce in `Sec-WebSocket-Key`, a
  `Sec-WebSocket-Accept` of `base64(sha1(key ‖ GUID))`, a persistent `Origin`
  header, **masked** client frames (and a masked frame *from* the server treated
  as a protocol error, which is what `hybiFrameHandler` does), one frame per
  `write` with `FIN` set and the `BinaryFrame` opcode — which is what frp selects
  so that a byte-oriented intermediary does not UTF-8-validate the tunnel — and
  `Ping` answered with a `Pong`. An offered `Sec-WebSocket-Extensions` fails the
  handshake rather than being ignored, because `permessage-deflate` would mean the
  payload is no longer a byte stream this side can read.
* **The layer order is the part that would have been silently wrong**, so it is
  pinned by a test that reads the first bytes off a socket. `websocket` puts TLS
  *inside* its frames — the default for that protocol, and the row that surprises
  people — while `wss` and `tcp`-with-TLS start with a TLS record. That comes
  from libnet's hook priorities, which are not the registration order:
  `DefaultAfterHookPriority` is 10, `WithTLSConfig` is `MaxUint64`, and `wss`
  overrides both at 100 and 110 to get the other arrangement. Three real-`frps`
  tests cover the transport end to end: a login, a 40 KB round trip through yamux
  inside the frames, and the same with TLS inside them.
* **`wss` is client-side only, and that is upstream's shape rather than a gap
  here.** `frps` sniffs its bind port for a `GET /~!frp` prefix and hands those
  connections to a websocket listener; nothing unwraps TLS and *then* looks for a
  websocket inside. frp's own end-to-end suite says so — "frps only supports ws,
  so there should be a proxy to terminate TLS before frps" — and tests `wss` by
  putting another `frpc` running `https2http` in front of the server. There is
  therefore no `wss` integration test here, because there is nothing to point it
  at; the layering test above is what covers the code, and `doc/compatibility.md`
  records the limitation.
* **A websocket frame parser had to be told where its own header ends.** With a
  one-byte length field the four-byte masking key is still part of the header, so
  a buffer that reached the end of the length field was reported as a complete
  header and the key was then read as payload. Caught by
  `a_short_prefix_does_not_parse_as_a_header`, which walks every prefix of a frame
  and requires all of them to be refused until the header is whole.
* **TLS on the control connection, which is the default path.** `transport.tls`
  was parsed and then ignored, and every dial was a plain TCP socket — so a
  server with `transport.tls.force = true` was simply unreachable, and every
  other deployment silently ran unencrypted at the transport layer while the
  config said otherwise. The client now builds the same stack of layers the Go
  client does, from the same options: `transport.tls.enable` (**true** by
  default), `serverName` (falling back to `serverAddr`), `certFile`/`keyFile`,
  `trustedCaFile`, and `disableCustomTLSFirstByte`. Two of those are easy to get
  backwards. The `0x17` head byte is written only when
  `disableCustomTLSFirstByte` is explicitly **false** — the option defaults to
  true, meaning the byte is *not* sent — and it is written *before* the
  handshake, which is the order the Go hooks run in. And verification is **off**
  unless `trustedCaFile` is set, which is Go's `InsecureSkipVerify = true`; the
  handshake and the transcript signature are still real, it is the chain and the
  name that are not checked. `AcceptAnyServerCert` therefore delegates
  `verify_tls12_signature`/`verify_tls13_signature` to the provider rather than
  stubbing them out.
* **The yamux session is generic over its socket.** It took a `TcpStream` and
  called `into_split()`, which only `TcpStream` has; it now takes anything
  `AsyncRead + AsyncWrite + Unpin + Send` and splits it with `tokio::io::split`.
  Nothing about multiplexing cares whether the bytes come out of a socket or a
  TLS record layer, and this is what makes TLS work with `tcpMux` on — which is
  the default combination.
* **Three new real-`frps` tests, one of which a plain-TCP client cannot pass.**
  `frps-integration-tls.toml` sets `transport.tls.force = true`, so the server
  rejects anything that is not a TLS handshake outright. `real_frps_accepts_a_login_over_tls`
  logs in against it, `real_frps_refuses_a_plain_login_to_a_tls_server` pins the
  other direction (a client that ignored `enable = false` and always spoke TLS
  would pass the first test alone), and `real_frps_carries_a_tcp_round_trip_over_tls`
  drives 40 KB through the whole stack — yamux inside a TLS session, every work
  connection and the bridge. The other twenty tests now dial TLS as well, since
  that is what the default config asks for.
* **`udp_round_trip` in the integration suite was a spinner, not a wait.** It
  retried 40 times, but on Windows a datagram to a closed UDP port draws an ICMP
  unreachable and the *next* read of that socket fails immediately — so the
  forty attempts completed in about as many microseconds and the loop gave up on
  a condition that would have cleared a moment later. It is now bounded by a
  ten-second deadline with a 50 ms pause between attempts, and it reports how
  many it made and what the last failure was. This is the defect behind the one
  test failure seen in fourteen full runs of the suite that could not be
  reproduced in twenty-five runs of the test on its own.
* **`udpPacketSize` is now the length a datagram is cut to.** It was parsed and
  then ignored, with every UDP socket read through a 65 507-byte buffer — the
  protocol ceiling rather than the configured value, so a local service answering
  a 2 000-byte reply had all 2 000 bytes delivered where the Go client delivers
  1 500. `pool.GetBuf(size)` hands the Go forwarder a slice of exactly that
  length, which makes this a truncation point rather than an allocation hint, and
  both places the Go client applies it are now applied here: a reply from a local
  service in a `udp` or `sudp` proxy, and a user's datagram at a `sudp` visitor's
  socket. Two liberties are taken with the value, and both are documented in
  `doc/compatibility.md`. A setting outside `1..=65507` is clamped and reported as
  a validation warning rather than obeyed, because Go's zero gives a zero-length
  read buffer — every datagram reads as empty, so the tunnel looks healthy and
  carries nothing — and a negative one panics in the allocator. And the cut is
  applied *after* the read rather than by it: on Unix a short `recvfrom`
  truncates silently, but on Windows it fails with `WSAEMSGSIZE`, and the Go
  forwarder treats a read error as the end of that user's goroutine — the socket
  is closed and the datagram lost rather than shortened. A real-`frps` test
  (`real_frps_truncates_a_udp_reply_to_udp_packet_size`) sends a 500-byte reply
  through a 64-byte setting and asserts it arrives 64 bytes long; it fails
  against the code without the trim.
* **Log output matches `golib` line for line.** `2006-01-02 15:04:05.000 [I]
  [service.go:332] [runID] …` — the fixed-width local timestamp, the one-letter
  level, the caller, and the run-id and proxy-name prefixes. The previous format
  used RFC3339, spelled the level `[INFO]`, and carried neither the caller nor
  the prefixes; the module comment claiming it was "line-for-line the same as the
  Go client's" was quoting a format that appears nowhere in frp or golib.
* **Every line carries a caller, and the Go-mirroring ones carry the *Go* line.**
  The public log functions take their location from `#[track_caller]`, so a
  message frp never prints says where in this implementation it came from
  (`[client/udp.rs:88]`) instead of leaving a blank column that reads as a logger
  bug. The messages that do reproduce a Go one name that Go line explicitly —
  `[sub/root.go:194]`, `[service.go:332]`, `[proxy/proxy_manager.go:183]`,
  `[control.go:174]` — because the field's whole purpose is to lead someone who
  knows frp back to the source, and a Rust line number there would send them
  nowhere. `connect to server error:` and the shutdown line now use Go's wording
  as well, with the backoff delay and the config path appended where this client
  has something extra to say.
* **`log.to` writes a file, and `log.maxDays` rotates it.** All three of
  `log.to`, `log.maxDays` and `log.disablePrintColor` were parsed and then
  ignored, so `log.to = "./frpc.log"` — the value the shipped Go example uses —
  produced no file and logs went to stdout regardless. A failed file destination
  now logs to stderr rather than taking the client down.
* **`role = visitor` in a legacy INI file now starts the visitor.** The sections
  were parsed and then reported as unsupported, which had been true once but was
  not any more: `stcp` and `sudp` visitors have worked for a while. Only `xtcp`
  is genuinely missing, and only it is reported now.
* **Legacy INI strips surrounding quotes from values.** `PreserveSurroundedQuote`
  is off on frp's parser, so `token = "abc"` authenticates with `abc`. Keeping
  the quotes produced a failure indistinguishable from a wrong token.
* **A visitor with no `bindAddr` gets `127.0.0.1`.** `complete()` only walked the
  proxies, so a visitor's address stayed empty and `":9000"` bound every
  interface — a quiet change in exposure for anyone expecting loopback.
* **An `xtcp` proxy is reported instead of silently bridging.** It was falling
  through to the ordinary TCP bridge, which would have accepted work connections
  the server never sends, producing a proxy that appears registered and carries
  nothing.
* **`conf/frpc.ini` and `conf/frpc_full_example.ini`.** The legacy example moved
  out of `conf/legacy/` so the example files pair up by name, and a minimal INI
  example now sits beside the minimal TOML one. Both document what the INI format
  actually does — the literal values, the quote stripping, and the inline-comment
  rule.
* **A stable `tcpMux` session.** The yamux keepalive sent its ping into the
  outbound queue and then waited for the reply *inside the one loop that drains
  that queue* — so the ping was never written and the reply it waited for could
  not arrive. Every session died one keepalive interval after it was established,
  which on a default 30-second interval is a client that reconnects forever at
  roughly 40-second intervals. The wait now runs in a task of its own, so the ping
  reaches the socket before anything is waited on. A regression test
  (`a_session_survives_a_keepalive_cycle`) fails against the old code.
* **The reconnect backoff matches Go's two managers.** Go builds a fresh
  `BackoffUntil` manager inside `loopLoginUntilSuccess` for each login phase and
  keeps a separate one for the gap after a session dies; one manager was reused
  for both, so the two curves shared their failure counts, and the login-phase
  copy inherited three 200 ms fast retries that Go does not configure there. The
  first login also used a flat 10-second interval where Go uses the same
  `1s → ×2 → 10s` curve, and a hand-rolled "healthy session" reset has been
  removed — Go has no such rule.
* **The read half no longer outlives a dead session.** A frame handler can park on
  the outbound queue or on a socket read, and a session that died while it was
  parked could not make it return — leaving the reader holding the socket's write
  half forever. Shutdown now wins that race.
* **A hostname `serverAddr` works.** `transport::connect` was parsing the joined
  `host:port` as a `SocketAddr`, which only accepts a literal address, so every
  config pointing at a DNS name failed with `invalid socket address syntax` while
  the identical config worked under the Go client — which hands the string to
  `net.Dial` and lets the resolver do its job. A literal still takes the
  no-resolver path.
* **`http`, `https` and `tcpmux` proxies.** All three are domain-routed by `frps`,
  so the local side is the ordinary TCP bridge and there was nothing to add to it:
  what was missing was the registration path being reachable. `frps` hands the
  client a work connection exactly as it does for `tcp`, and the client joins it
  to `localIP:localPort`.
* **`wireType` and a `wireType`-shaped plugin.** A proxy can now register under a
  different type name than it runs as — which is what `virtual_net` needs — and a
  proxy whose local side this client cannot run is reported and skipped instead of
  taking the whole config down with it.
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
* **`the_full_legacy_ini_example_parses` was asserting a report that had stopped
  being true.** When `stcp` visitors started working, `[secret_tcp_visitor]`
  stopped being skipped — and the test still required the warning to name it, so
  two of that test's three assertions could not hold at once and the suite was red
  on the committed tree. It now checks both halves: the `xtcp` visitor is the one
  reported, and the `stcp` visitor is converted, with its kind, bind address and
  port asserted.

## 0.1.0 — unreleased

First cut. The compatibility claim is testable end to end: a stock Go `frps`
accepts this client's login, and a registered `tcp` proxy carries real bytes from
the port the server published through to a local service and back.

Build and release:

* No C dependency in the frp protocol stack — the AES-CFB, snappy framing,
  SHA-1/HMAC/PBKDF2 and the yamux multiplexer are all pure Rust. The one C
  dependency is `ring`, which `rustls` uses for the TLS handshake; it is a build
  requirement for a C compiler, not a runtime link to a crypto library, and zig
  supplies that compiler for the cross builds as well as the linker. The process
  still carries no crypto library's per-thread state or arena allocators.
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
  routes an `http` request by `Host` to a local HTTP service and carries a
  `tcpmux` `HTTP CONNECT` through to a local TCP service,
  survives a proxy whose local service is down,
  and serves the admin API over real HTTP including `stop` and the credential
  check.

## Not yet implemented

Everything here is *parsed and reported* rather than silently ignored: either the
proxy is skipped with a warning naming it, or `--check-config` says so. A config
that uses one of these will not fail to load, and the option will not take
effect.

* `useCompression` on work connections, and `useEncryption`/`useCompression` on
  `udp` proxies or visitors: a proxy that asks for either has its connections
  refused rather than bridged unwrapped, since the registration told the server
  otherwise.
* The websocket, WSS and KCP transports. TLS is not on this list — it is
  `transport.tls`, it sits on top of `tcp`, and it is implemented.
* The client-side plugins — `http_proxy`, `socks5`, `static_file`,
  `unix_domain_socket`, `tls2raw`, `http2http` and the `https2*` family — and
  their `http2https` shape. A proxy naming one is skipped.
* The `xtcp` proxy and visitor, which need NAT hole punching. Everything else
  registers and runs: `tcp`, `udp`, `http`, `https`, `tcpmux`, `stcp` and `sudp`.
* Health checks. A `healthCheck` proxy registers and is never withdrawn, because
  nothing polls it.
* `dnsServer`, `natHoleStunServer`, `store`, `webServer.assetsDir`,
  `webServer.pprofEnable`, and OIDC authentication. `auth.method = "oidc"`
  validates and then authenticates with the token.
* YAML and JSON configs. Go sniffs all three formats by content; this
  distinguishes legacy INI from TOML only. A `.yaml` or `.json` file is read as
  TOML and fails rather than being misread.
* `/api/visitor/{name}/config`, `/api/store/*`, and the static dashboard assets.
* Wire protocol v2. `msg.rs` encodes and decodes both framings, but the v2
  `ClientHello` exchange is not implemented, so only v1 is usable end to end —
  which also means the v2-only `binary-v1` UDP packet codec is out of reach.
* The rename-retry strategy is parsed but not applied.
