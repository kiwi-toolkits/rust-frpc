# Compatibility with the Go implementation

The baseline is `fatedier/frp` `dev` at `d20a2329` (version string `0.71.0`).
Behaviour is matched against that source tree. This file records the decisions
that a reader of both implementations would otherwise have to reverse-engineer,
and the places where this client deliberately differs.

## Wire protocol

* **Application-layer crypto is unconditional.** The v1 control connection is
  always wrapped in `PBKDF2-HMAC-SHA1(token, "frp", 64) → AES-128-CFB`, whatever
  `transport.tls.enable` says, and regardless of `useEncryption`. The salt is
  `"frp"` because frp overrides `golib`'s `"crypto"` default in an `init()` on
  both sides.
* **The IV is lazy.** It is written on the first `Write`, not at construction, so
  a connection that never sends anything transmits nothing. A reader must block
  for 16 bytes before its first payload byte.
* **Compression is snappy *framed*, not block**, and it wraps the encryption:
  the bytes on the wire are `snappy(aes_cfb(plaintext))`, so the IV lives inside
  the compressed stream and decompression happens first. The framing has been
  cross-checked against `golang/snappy` in both directions: a frame Go produced
  decodes here, and a frame this crate produces is byte-identical to Go's and
  decodes with Go's reader. The chunk checksum is CRC-32C with the spec's
  rotate-and-add mask, pinned against a value Go wrote.
* **`privilege_key` / `sign_key`**: `hex(md5(secret ‖ decimal(timestamp)))`, with
  no separator between the two parts, lowercase hex, Unix seconds.
* **`omitempty` does nothing to a struct-typed field.** `Login.client_spec` and
  `NatHoleResp.detect_behavior` are therefore always on the wire, as `{}` when
  empty. `Message` reproduces that rather than "fixing" it.
* **JSON is Go-flavoured**: map keys sorted, and `<` `>` `&` escaped as
  `<`, `>`, `&`. Bodies written here are byte-identical to the Go
  ones.
* **v1 framing** is `[type byte][i64 BE length][JSON]` with a 10240-byte body
  cap, not the "JSON array" the older docs describe.
* **v1 vs v2 is chosen locally, never negotiated.** A v2 client sends the 7-byte
  magic first; a v1 client sends its first message. Pointing a v2 client at a
  v1-only server fails rather than falling back, which is why v1 is the default
  here.
* **`StartWorkConn` ports are `uint16`** on the Go side, so an out-of-range port
  truncates silently instead of erroring.
* **No version gating exists** in the data path. `Login.version` is recorded and
  logged, never compared, so this client reports its own version string.

## Configuration

* Format detection is by **content**, not extension: a file that parses as INI
  and contains a `[common]` section is legacy INI, everything else goes through
  the TOML/YAML/JSON path. `frpc.ini` and `frpc.toml` are interchangeable.
* Strict unknown-field handling is **on by default** (`--strict-config`) and
  applies recursively, including inside `proxies[]` and plugin objects.
* Defaults are applied by a `Complete()` pass after loading, and two of them are
  counter-intuitive: `transport.tls.enable` defaults to **true**, and
  `heartbeatInterval`/`heartbeatTimeout` default to **-1 (disabled)** whenever
  `tcpMux` is on, which it is by default.
* Legacy INI keeps `IgnoreInlineComment`: a trailing `# comment` on a value line
  becomes **part of the value**. It is faithful, not a bug.
* Legacy INI prefix handling is asymmetric: `meta_*` strips its prefix, `plugin_*`
  keeps it, `header_*` strips it.

## Multiplexing

* `transport.tcpMux` defaults to **on**, on both sides, and it is a **server-side
  decision as much as a client-side one**: `frps` wraps each accepted connection
  in yamux when *its* setting is on, whatever the client configured. A client
  that disagrees fails with an early EOF rather than a clear error, so the two
  must match. `tests/fixtures/` therefore ships two frps configs, one for each
  setting.
* The yamux frame layout, flags, window sizes and id parity are pinned against
  the `fatedier/yamux` v0.2.0 fork in `src/proto/mux.rs`, with tests asserting
  each constant. A multiplexer that disagrees about a window or a flag does not
  degrade — it corrupts the stream — so these are not treated as implementation
  details.

## The control session

* **`StartWorkConn` is not an answer, it is a delivery.** `frps` keeps the
  connections a client opens in a pool and replies to `NewWorkConn` only when a
  user connection actually takes one — which may be minutes later, or never. So
  the client must not block on it: this loop hands the whole exchange to its own
  task per `ReqWorkConn`. Go reaches the same behaviour by registering the handler
  with `msg.AsyncHandler`, which runs it in a fresh goroutine.
* **Proxy phases match the wrapper**: `new`, `wait start`, `running`,
  `start error`, re-announced on a 3-second tick once 20 seconds have passed
  without an answer. A `start error` is retried rather than fatal, because in a
  real deployment the usual cause is a port that is briefly still in use.
* **`CloseProxy` on shutdown**, so the server frees the port immediately instead
  of waiting for the control connection to time out. `CloseProxy` has no reply,
  so the sends are fire-and-forget.
* **The bridge is deliberately single-task**, driven by a `select!` over both
  directions with a 16 KiB buffer each. A stalled write therefore pauses the other
  direction. The Go server accepts the same coupling by drawing its buffers from a
  shared pool, and the cost is invisible for the request/response traffic a proxy
  actually carries.
* **A work connection that cannot be opened is not a session failure.** The local
  service being down, or the stream being refused, drops that one connection and
  is logged; the control session and every other proxy carry on.

## The admin API

The routes, the response shapes and the auth behaviour are the Go client's,
because `frpc status`, `frpc reload`, `frpc stop` and the dashboard all speak this
protocol — a client that answers differently is one those tools cannot manage.

* `/healthz` is **outside** the auth check, matching the Go router: it is what a
  supervisor polls and it reveals nothing.
* `GET /api/status` groups by proxy type, sorts by name within a type, and uses
  the Go field names including the underscore ones (`local_addr`, `remote_addr`).
  The remote address is only filled in when there is no error — a stale address
  would be worse than none — and for `tcp`/`udp` it is prefixed with the server
  address, because `frps` reports a bare `:port`.
* `PUT /api/config` **validates before it writes**, so a config the client cannot
  load is never persisted, and writes through a temporary file plus a rename so a
  crash mid-write leaves the previous file intact.
* Errors use the Go envelope, `{"code": <status>, "msg": "..."}`, and a failed
  authentication gets the `WWW-Authenticate` challenge and the middleware's 200ms
  delay. Credentials are compared in constant time.
* `reload` is applied over a **fresh control session** rather than inside the
  running one, which is what the Go client does. The proxies the old config had
  are closed by the ordinary shutdown path before the new ones are registered, so
  a proxy dropped from the file really goes away.
* `/metrics` is an addition, not a match — see the differences table.

* **UDP is a different shape from TCP.** The server multiplexes every user's
  datagrams onto a *single* long-lived work connection, puts the user's address in
  `UDPPacket.remote_addr`, and expects the answer to carry it back. The client
  keeps one local socket per user for exactly that reason — it is what stops one
  user's reply reaching another — and drops sockets idle for 30 seconds, matching
  the read deadline in `pkg/proto/udp/udp.go`. The work connection is pinged every
  30 seconds because the server closes it after 60 without a message
  (`server/proxy/udp.go`).
* **`UDPPacket.content` is base64**, not a JSON array of numbers: Go marshals a
  `[]byte` that way and serde does not. See `msg::go_types`.
* **`UDPAddr.IP` is text**, not base64 and not bytes. Go's `encoding.TextMarshaler`
  wins over the `[]byte` rule for a named type that implements it, so a naive port
  emits `"wAAC Cg=="` where the server expects `"192.0.2.10"`.
* **Only the v1 framing is usable.** `v2` framing exists but the `ClientHello`
  exchange is not implemented, so the v2-only `binary-v1` UDP packet codec is out
  of reach as well — `NewUDPPacketReadWriter` rejects a non-empty codec under v1.
* **A hostname reaches the resolver, not the address parser.** `serverAddr` is a
  name in almost every real deployment, and the Go client never parses it — it
  joins `serverAddr` and `serverPort` and hands the result to `net.Dial`. Doing
  the same here means trying a literal parse first (so a host with no resolver
  still works) and falling back to `lookup_host`, trying each address it yields,
  because a name that resolves to several addresses only needs one of them to
  answer.
* **`http`, `https` and `tcpmux` are `tcp` on this side.** `frps` owns every
  routing decision — domains, subdomains, locations, `HTTPUser`, the `tcpmux`
  muxer — and what reaches the client is an ordinary work connection, which it
  bridges to `localIP:localPort` exactly as it does for a `tcp` proxy. There is
  therefore no per-type local code; the registration message is the whole
  difference, and getting the type string wrong is the only way to get it wrong.
* **A `tcpmux` `CONNECT` is routed by its authority**, so the request is
  absolute-form (`CONNECT host:port HTTP/1.1`) and carries no `Host`. The server
  answers a bare `HTTP/1.1 200 OK` with a `Content-Length` and then hijacks the
  connection; the tunnel starts after the blank line.
* **`wireType` changes only what the server is told.** The local side is derived
  from `type`, so a proxy can be registered as one the server will accept while
  running as another — which is what `virtual_net` uses it for. A `wireType` this
  client cannot run is reported and the proxy is skipped rather than registered.

* **A visitor's signature is over the proxy's secret key**, not the auth token:
  `hex(md5(sk ‖ decimal(timestamp)))`. The per-connection crypto is keyed on that
  same secret while the control connection is keyed on the token, so a single
  visitor session uses two keys. The name on the wire is the *target* proxy's
  (`serverUser` + `serverName`, with the local `user` as the fallback for
  `serverUser`), never the visitor's own.
* **`stcp` needs no special-casing on the proxy side.** The server still asks the
  proxy's client for a work connection and joins it to the visitor connection
  itself, so an `stcp` proxy is served by the ordinary TCP bridge. Verified against
  a real `frps`: a version that assumed `stcp` had no work connections dropped
  every one of them, and the symptom was a visitor that connected and then simply
  never heard back.
* **A `sudp` session belongs to the visitor, not to a user.** `SUDPVisitor.Run`
  starts `ForwardUserConn` on the bound socket, which tags every datagram with the
  address it came from and pushes it into one channel; `dispatcher` opens a visitor
  connection for the *first* datagram to land there and `worker` writes every later
  datagram — whoever sent it — onto that same connection, each still carrying its
  own `remote_addr`. So the tag is the routing mechanism and a second user is
  *not* turned away; an implementation that scopes a session to one user, as this
  one briefly did, silently drops the second user's traffic for as long as the
  first keeps talking. A session ends on a 30-second read deadline on the visitor
  connection, and the next datagram opens a new one.

## Deliberate differences

Everything below is a choice, not an oversight. Each is documented in the user
docs too.

| Area | This client | Why |
| :--- | :--- | :--- |
| `frps` | Not implemented | Out of scope; the Go server is the counterpart. |
| `useCompression` on work connections | Refused | Not implemented yet. The registration told the server the connection is compressed, so bridging it in the clear would corrupt the stream rather than fail loudly. |
| `useEncryption`/`useCompression` on a `udp` proxy | Refused | Same reason: the wrapping applies to the packet stream itself and is not wired up, so the work connection is refused rather than bridged unwrapped. |
| Proxy types | All but `xtcp`, so far | The rest of the registration messages already exist in `msg.rs`; the local side of each type is the work. |
| Plugins | None, yet | A config naming one is reported and that proxy is skipped, so the rest of the file still runs. |
| Visitors | `stcp` and `sudp` | `xtcp` needs NAT hole punching, and a config naming it is skipped with a warning rather than half-run. |
| Wire protocol | v1 only | The v2 framing is implemented and tested, but the `ClientHello`/`ServerHello` exchange is not, so a `v2` config cannot complete a session. |
| Admin API | No HTTP framework | Written on `tokio` directly, because the surface is eight routes and a framework costs more binary size than the routing it replaces — which matters for a crate whose point is the size of the process. |
| `/metrics` | Added, off by default | Proxy/connection/traffic counters in plain text, no Prometheus client library. |
| `--check-config` | Added | Validate and print the normalized config, then exit. For CI and pre-deploy checks. |
| `log.format = "json"` | Added | For log pipelines. Text stays the default, byte-compatible with the Go output. |
| `quic` transport | Not supported | The Rust QUIC stack costs binary size and build time; `kcp` covers the same weak-network case for now. |
| Version string | `rust-frpc.<version>` | `frps` logs it and the dashboard shows it, so an operator can tell which client is which. No compatibility impact. |
| Rename retry | Parsed, not yet applied | Same `ex_1_ → ex_2_ → ex_3_` sequence as `rust-tiny-frpc`. Turning it on changes a proxy's public name, so it should be a decision — and it is off by default. |
