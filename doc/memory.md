# Memory budget

The reason this project exists is that a Go `frpc` holds 20–40 MB resident, which
is a lot on the ARMv7 boards this is meant for. The target here is **under 5 MB
idle** and **under 20 MB with 100 TCP proxies registered**.

This file records what the target actually costs, so a future change that doubles
the footprint is a decision rather than an accident.

## Where it is spent

* **The async runtime.** The default is a single-threaded tokio runtime. The
  client is I/O-bound and almost all of its work is copying bytes between two
  sockets, so extra worker threads buy nothing and each one costs a stack plus
  its own task queue. A multi-threaded runtime is opt-in, for `kcp`/`quic` where
  a dedicated thread helps.
* **Buffers.** Bridging uses one pooled 16 KiB buffer per direction, matching
  `golib`'s `io.Join`. Queues are bounded and small; the default is deliberately
  not "one buffer per connection per direction forever".
* **Idle work.** A registered proxy that is not carrying traffic should not own a
  task. Go spawns a status-check goroutine per proxy; here a single timer drives
  every proxy's status tick, so 100 proxies cost one wakeup, not 100.
* **Logging.** A record below the configured level allocates nothing. Timestamps
  are formatted lazily against a cached second.
* **No C dependencies at all.** Everything — the AES-CFB, the snappy framing, the
  SHA-1/HMAC/PBKDF2, the yamux multiplexer — is pure Rust. That keeps the binary
  small and, more to the point, keeps the process free of a crypto library's
  arena allocators and its per-thread state.

## Measuring

```bash
RUN_REAL_FRPS_TESTS=1 \
FRPS_BIN=/path/to/frps \
FRPS_CONFIG=tests/fixtures/frps-integration.toml \
FRPC_BIN=target/release/frpc \
cargo test --test memory -- --ignored --nocapture --test-threads=1
```

The harness spawns the **release binary as its own process** — an in-process
measurement would include the test runtime and every earlier test's unreleased
allocations — registers one proxy or a hundred against a real `frps`, waits for
them all to be published, then samples for six seconds and gates on the last
reading. A value that keeps climbing is a leak, and reporting only the minimum
would hide it.

### What the numbers are, measured 2026-09-25 on Windows 11 / x86_64, release profile

| | working set | private commit |
| :--- | ---: | ---: |
| `fn main` that sleeps (the platform floor) | 4356 kB | 692 kB |
| frpc, 1 proxy, idle | 6600 kB | 1268 kB |
| frpc, 100 proxies, idle | 7264 kB | 1948 kB |

**The floor matters, and it is why the gate does not use the same metric
everywhere.** On Windows *any* Rust binary holds about 4.3 MB resident before it
does anything — that is the loader, the CRT and the page tables — so a 5 MB
working-set budget there would be testing the platform rather than this crate. The
Windows gate is therefore on private commit, which is what the process itself
asked for; Linux, where the floor is far lower, gates on the working set, which is
what the stated 5 MB target means. Both numbers are printed either way, and
`FRPC_RSS_BUDGET_KB` / `FRPC_RSS_100_BUDGET_KB` raise the budget for a platform
with a different baseline.

The honest reading of the table above is that **the hundred-proxy figure has
plenty of headroom and the idle figure does not**: 1.2 MB private is comfortably
inside the target, but the 6.5 MB working set would not have been, on a platform
whose floor were lower. So the idle number on Linux is the one to watch, and the
CI job runs there.

### What is not done

Anything that trades memory for speed without a measurement to justify it. If a
change needs a bigger buffer or a cache, it should come with the number it moves.

## The numbers are only half the claim

The tables above are this machine. The **compatibility** claim — that a stock Go
`frps` accepts this client, hands it a public port, and lets real bytes through —
is verified against a server built from source in CI, and that is the part a
number cannot stand in for. `doc/compatibility.md` is where the two are reconciled.
