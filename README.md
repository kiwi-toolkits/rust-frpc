# rust-frpc

[中文](README_zh.md)

A memory-frugal Rust implementation of the frp client, wire-compatible with the
Go [`frps`](https://github.com/fatedier/frp).

The goal is a drop-in `frpc`: same configuration files, same command line, same
admin API, and the same bytes on the wire. A Go server never learns that the
client is not the Go one.

## Status

Early, but the compatibility claim is now testable end to end: `frpc verify
--server` completes a real login against a stock Go `frps`, and
`tests/real_frps.rs` asserts it.

| Layer | State |
| :--- | :--- |
| frp crypto (PBKDF2 → AES-128-CFB, snappy framing) | done |
| Message set and v1/v2 framing | done |
| Config (TOML + legacy INI, strict/lenient) | done |
| Login handshake against a real `frps` | done |
| yamux (`tcpMux`, the default) | done |
| Control loop (heartbeat, proxy registration, work conns) | next |
| Transports other than plain TCP | next |

`frpc` still cannot carry traffic — it logs in and says so. See the
[roadmap](#roadmap).

## Try it

```bash
# Parse a config and print what the defaults resolved to.
cargo run -- --check-config -c conf/frpc.toml

# Check a config, then log in to the server it names and report the result.
cargo run -- verify -c conf/frpc.toml --server
```

`verify --server` deliberately stops at the login: registering a proxy would
create a public port on somebody's server, which is not what a health check
should do as a side effect. The `Login` exchange already proves the framing, the
crypto and the token signature, which is the part that has to be right.

To run a tunnel, put a proxy in the config and start the client:

```toml
serverAddr = "example.com"
serverPort = 7000
auth.token = "secret"

webServer.port = 7400        # optional: the admin API

[[proxies]]
name = "ssh"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6000
```

```bash
frpc -c frpc.toml            # the tunnel runs until interrupted
```

With `webServer.port` set, a running client can be managed the same way the Go
client is managed:

```bash
frpc status -c frpc.toml     # one table per proxy type
frpc reload -c frpc.toml     # re-read the config file
frpc stop    -c frpc.toml    # shut the client down

curl localhost:7400/healthz  # unauthenticated, for a supervisor
curl localhost:7400/api/status
curl localhost:7400/metrics  # plain text counters
```

`reload` re-reads the file and applies it over a fresh control session, which is
the same thing the Go client does and takes about a second. Nothing is applied
from a half-parsed file: an unreadable config is logged and ignored.

## Compatibility

* **Baseline**: `fatedier/frp` `dev`, version `0.71.0`. Behaviour is matched
  against that tree, not against release notes. The integration test in
  `tests/real_frps.rs` runs against whatever `frps` binary you point it at; it
  has been verified against `0.61.0`.
* Wire protocol **v1**, which is the default and what older servers understand.
  `Transport.tcpMux` on or off both work.
* Transports: plain `tcp` today, with or without `tcpMux`. `tls`, `websocket`
  and `kcp` are next. `quic` is deliberately out of scope for now — see the
  roadmap.
* Proxies: `tcp`, `udp`, `stcp` and `sudp`. The other four types are accepted by
  the config layer and rejected at registration for now.
* Visitors: `stcp` and `sudp`, which is how those proxies are reached — nothing is
  published on the server, so the visitor binds a local port (or, for `sudp`, a UDP
  socket) and names the proxy it wants. `xtcp` visitors are skipped with a warning.
  A `sudp` session belongs to the visitor rather than to a user: the first datagram
  opens it, later datagrams from any user ride on it, and each carries the address
  it came from, which is how the answer gets back to the right one.
* Not yet wired up, and each refused rather than half-done: wire protocol `v2`
  (the framing exists in `msg.rs` but the `ClientHello` exchange does not),
  `useCompression` on a work connection, and `useEncryption`/`useCompression` on a
  `udp` proxy.
* The admin API serves `/healthz`, `/api/status`, `/api/config` (GET and PUT),
  `/api/proxy/{name}/config`, `/api/reload`, `/api/stop` and `/metrics`, with the
  Go client's paths and response shapes. `/api/visitor/{name}/config`,
  `/api/store/*` and the static dashboard assets are not there yet.
* `transport.tcpMux` is a server-side decision as much as a client-side one:
  `frps` wraps whatever it accepts in yamux when its own setting is on. The two
  must match, so `tests/fixtures/` ships an frps config for each setting.

## Testing

```bash
cargo test                       # unit tests, plus config parity against the Go examples
```

`tests/config_parity.rs` parses the Go repository's own `frpc_full_example.toml`
and `frpc_legacy_full.ini`, so a key added upstream that this client does not
know about fails the suite rather than being discovered in production.

The end-to-end test needs a real `frps` and is ignored by default:

```bash
RUN_REAL_FRPS_TESTS=1 \
FRPS_BIN=/path/to/frps \
FRPS_CONFIG=tests/fixtures/frps-integration.toml \
cargo test --test real_frps -- --ignored --test-threads=1
```

It asserts that a stock `frps` accepts this client's login (with and without
`tcpMux`), rejects a wrong token, answers a heartbeat on the encrypted control
connection, accepts a reconnect that replays the previous run id, and — the one
that matters most — carries a real TCP round trip through a registered proxy to a
local service and back, over both the multiplexed and the plain transport. UDP is
covered the same way, and so are the two proxy types that publish nothing: `stcp`
and `sudp` each carry a round trip through a visitor, with a wrong secret key
refused and two users kept apart. It also drives the admin API over HTTP,
including `stop` and the credential check.

## Memory

The point of the exercise. The target is a resident set under 5 MB idle and
under 20 MB with a hundred TCP proxies, against the 20–40 MB a Go `frpc`
typically holds. The design choices that get there are written down in
[`doc/memory.md`](doc/memory.md).

The budget is enforced rather than asserted:

```bash
RUN_REAL_FRPS_TESTS=1 \
FRPS_BIN=/path/to/frps \
FRPS_CONFIG=tests/fixtures/frps-integration.toml \
FRPC_BIN=target/release/frpc \
cargo test --test memory -- --ignored --nocapture
```

That spawns the release binary as its own process, registers one proxy or a
hundred against a real `frps`, and gates on its resident set. The recorded
numbers, including the platform floor they have to be read against, are in
[`doc/memory.md`](doc/memory.md).

## Build

```bash
cargo build --release
```

The release profile is tuned for size (`opt-level = "z"`, fat LTO, `strip`,
`panic = "abort"`). `--profile release-fast` is the same shape but links quickly,
which is what you want while developing.

The crate produces two binaries with identical behaviour:

```bash
target/release/frpc        # the drop-in name
target/release/rust-frpc   # same program, for when both are installed
```

For the ARM Linux boards this is aimed at, see
[`doc/build-linux-arm.md`](doc/build-linux-arm.md) — `scripts/build-arm.sh` and
`scripts/build-arm.ps1` cross-compile to `armv7` and `aarch64` musl. There is no C
dependency anywhere in the crate, so zig is only supplying the linker and no
cross-gcc package is needed.

## Configuration

TOML, plus the legacy `[common]` INI format. The format is decided by content
rather than by file extension — a file that parses as INI and has a `[common]`
section is treated as INI, exactly as the Go client does — so an existing
`frpc.ini` keeps working when renamed.

YAML and JSON are on the Go client's path too and are not supported here yet; a
YAML config fails with a TOML parse error rather than being misread.

See [`conf/`](conf/) for a minimal example and a full one.

## Roadmap

1. ~~**M0** — skeleton, config parsing, `--check-config`.~~ done
2. ~~**M1** — login handshake against a real `frps`.~~ done
3. ~~**M2** — proxy registration and a working TCP round trip.~~ done
4. ~~**M3** — the admin API, `frpc reload|status|stop`.~~ done
5. **0.1.0** — CI, release artefacts, the memory budget enforced rather than
   asserted.
6. Then: the remaining proxy types, the client-side plugins, visitors, xtcp,
   the `tls`/`websocket`/`kcp` transports, and the rest of the admin API.

## License

Apache-2.0.
