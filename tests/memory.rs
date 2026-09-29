//! Resident-set measurement against a real `frps`.
//!
//! Ignored by default, because it needs a real `frps` binary, exactly like
//! `tests/real_frps.rs`. Run it with:
//!
//! ```text
//! RUN_REAL_FRPS_TESTS=1 \
//! FRPS_BIN=/path/to/frps \
//! FRPS_CONFIG=tests/fixtures/frps-integration.toml \
//! FRPC_BIN=target/release/frpc \
//! cargo test --test memory -- --ignored --nocapture
//! ```
//!
//! The budget is the reason this crate exists — under 5 MB idle, under 20 MB with
//! a hundred TCP proxies — so it is measured rather than asserted in a README.
//!
//! Two things about the measurement are worth stating, because either one on its
//! own would make the number misleading.
//!
//! **It measures the shipped binary as its own process.** An in-process
//! measurement would include tokio's test runtime, the freed-but-unreturned
//! allocations of every earlier test, and the harness's own buffers. So this
//! spawns `frpc` as a child and reads the child. It therefore measures the profile
//! you built: a debug build is several times larger, and the numbers only mean
//! anything for a release build.
//!
//! **Two numbers are read, and the gate uses one of them.** The working set is
//! what the OS is keeping resident; the private bytes are what the process itself
//! has committed. On Windows the working set has a floor of about 4.3 MB for *any*
//! Rust binary — measured, not assumed: a `fn main` that sleeps holds 4356 kB — so
//! gating on it there would test the platform's page tables rather than this
//! crate. On Linux that floor is far lower and the working set is exactly what the
//! stated 5 MB target means. So each platform gates on the metric that actually
//! measures the client, and both numbers are printed either way.

#![allow(clippy::field_reassign_with_default)]

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use rust_frpc::config::{self, AuthClientConfig, ProxyConfig, ProxyKind, Qos};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

const CONTROL_PORT: u16 = 17_000;
const TOKEN: &str = "rust-frpc-integration";

/// The first public port the generated proxies ask for.
///
/// A hundred of them are registered at once, so this and the ninety-nine that
/// follow must not collide with the control port or with anything a developer is
/// likely to be using.
const FIRST_REMOTE_PORT: u16 = 17_400;

/// How long to watch the client before deciding what its steady state is.
const SETTLE: Duration = Duration::from_secs(6);

/// How often to sample the resident set while it settles.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(500);

/// The stated targets: under 5 MB idle, under 20 MB with a hundred proxies, both
/// measured as the working set — which is what those figures mean on Linux.
#[cfg(not(windows))]
const IDLE_BUDGET_KB: u64 = 5 * 1024;
#[cfg(not(windows))]
const HUNDRED_BUDGET_KB: u64 = 20 * 1024;

/// The same targets on Windows, measured as private commit instead — see the
/// module docs for why the working set is the wrong metric there.
#[cfg(windows)]
const IDLE_BUDGET_KB: u64 = 5 * 1024;
#[cfg(windows)]
const HUNDRED_BUDGET_KB: u64 = 15 * 1024;

struct Fixture {
    bin: String,
    config_path: String,
    frpc: String,
}

fn fixture() -> Option<Fixture> {
    std::env::var_os("RUN_REAL_FRPS_TESTS")?;
    Some(Fixture {
        bin: std::env::var("FRPS_BIN").expect("FRPS_BIN is required"),
        config_path: std::env::var("FRPS_CONFIG")
            .expect("FRPS_CONFIG is required; use tests/fixtures/frps-integration.toml"),
        // Defaults to the release profile, which is the one whose size matters.
        frpc: std::env::var("FRPC_BIN").unwrap_or_else(|_| "target/release/frpc".to_string()),
    })
}

fn budget(variable: &str, default: u64) -> u64 {
    std::env::var(variable)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

async fn wait_for_port(port: u16, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "nothing started listening on {port} within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Starts the fixture `frps`.
///
/// `kill_on_drop` so a panicking assertion cannot leave the server holding the
/// control port for every later run — including the next one in CI.
fn start_frps(bin: &str, config: &str) -> Child {
    Command::new(bin)
        .arg("-c")
        .arg(config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("start frps")
}

/// Writes a config with `count` TCP proxies, all pointing at `local_port`.
///
/// A hundred proxies on one local port rather than a hundred services, because
/// what is being measured is the client's per-proxy bookkeeping — a local service
/// is only dialed when a connection arrives, and none do here.
fn write_config(path: &PathBuf, count: u16, local_port: u16) {
    let mut config = config::ClientConfig::default();
    config.common.server_addr = "127.0.0.1".into();
    config.common.server_port = CONTROL_PORT;
    config.common.auth = Some(AuthClientConfig {
        method: "token".into(),
        token: TOKEN.into(),
        ..Default::default()
    });
    for index in 0..count {
        config.proxies.push(ProxyConfig::new(
            format!("p{index}"),
            None,
            ProxyKind::Tcp {
                remote_port: FIRST_REMOTE_PORT + index,
            },
            Qos {
                local_ip: "127.0.0.1".into(),
                local_port,
                ..Qos::default()
            },
            None,
        ));
    }
    config.complete();

    let text = toml::to_string_pretty(&config).expect("render the config");
    std::fs::write(path, text).expect("write the config");
}

/// Starts the client binary and waits for every proxy to be published.
async fn start_client(frpc: &str, config_path: &PathBuf, count: u16) -> Child {
    let child = Command::new(frpc)
        .arg("-c")
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start frpc");

    // Every proxy has to be up before the measurement means anything: a client
    // that has only registered half of them reports half the memory.
    for index in 0..count {
        wait_for_port(FIRST_REMOTE_PORT + index, Duration::from_secs(30)).await;
    }
    child
}

/// What one run measured.
#[derive(Debug, Clone, Copy)]
struct Reading {
    /// The last sample of each, and what the budget is checked against: a value
    /// that keeps climbing is a leak, and reporting only the minimum would hide it.
    ws: u64,
    private: u64,
    /// The peak working set over the settle window.
    ws_peak: u64,
}

impl Reading {
    /// The metric this platform is gated on.
    #[cfg(windows)]
    fn gated(&self) -> u64 {
        self.private
    }

    /// The metric this platform is gated on.
    #[cfg(not(windows))]
    fn gated(&self) -> u64 {
        self.ws
    }

    /// What the gated metric is called, so a failure names it.
    #[cfg(windows)]
    const GATED_LABEL: &'static str = "private commit";

    /// What the gated metric is called, so a failure names it.
    #[cfg(not(windows))]
    const GATED_LABEL: &'static str = "working set";
}

/// Samples the client's memory until it settles.
async fn measure(child: &Child) -> Reading {
    let pid = child.id().expect("the client should still be running");
    let mut samples = Vec::new();
    let deadline = tokio::time::Instant::now() + SETTLE;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(SAMPLE_INTERVAL).await;
        samples.push(process_memory_kb(pid));
    }
    let (ws, private) = *samples.last().expect("at least one sample");
    Reading {
        ws,
        private,
        ws_peak: samples.iter().map(|(ws, _)| *ws).max().unwrap(),
    }
}

/// A process's (working set, private bytes), in kilobytes.
///
/// A zero becomes an assertion failure rather than a passing budget: a real client
/// is never 0 KB, so a platform that cannot answer must fail loudly instead of
/// reporting a client that fits in nothing.
fn process_memory_kb(pid: u32) -> (u64, u64) {
    let value = process_memory_kb_inner(pid);
    assert!(
        value.0 > 0 && value.1 > 0,
        "could not read the memory of process {pid}; the gate cannot be enforced \
         on this platform"
    );
    value
}

#[cfg(target_os = "linux")]
fn process_memory_kb_inner(pid: u32) -> (u64, u64) {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return (0, 0);
    };
    // `VmRSS` is the resident set; `VmData` is the data segment, which is the
    // closest Linux analogue of Windows' private bytes.
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0u64)
    };
    (field("VmRSS:"), field("VmData:"))
}

/// Windows, through `GetProcessMemoryInfo`.
///
/// Declared here rather than pulling in `windows-sys` for it: this is two calls
/// and one struct, and the crate's whole point is the size of the binary.
#[cfg(windows)]
fn process_memory_kb_inner(pid: u32) -> (u64, u64) {
    use std::ffi::c_void;

    // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, which is what
    // `GetProcessMemoryInfo` documents itself as needing.
    const ACCESS: u32 = 0x0400 | 0x0010;

    #[repr(C)]
    #[derive(Default)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn K32GetProcessMemoryInfo(
            process: *mut c_void,
            counters: *mut ProcessMemoryCounters,
            size: u32,
        ) -> i32;
    }

    unsafe {
        let handle = OpenProcess(ACCESS, 0, pid);
        if handle.is_null() {
            return (0, 0);
        }
        let mut counters = ProcessMemoryCounters::default();
        counters.cb = std::mem::size_of::<ProcessMemoryCounters>() as u32;
        let ok = K32GetProcessMemoryInfo(
            handle,
            &mut counters,
            std::mem::size_of::<ProcessMemoryCounters>() as u32,
        );
        CloseHandle(handle);
        if ok == 0 {
            return (0, 0);
        }
        // `pagefile_usage` is the private commit — Windows' answer to "what has
        // this process actually asked for", as opposed to what is resident.
        (
            (counters.working_set_size / 1024) as u64,
            (counters.pagefile_usage / 1024) as u64,
        )
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn process_memory_kb_inner(_pid: u32) -> (u64, u64) {
    (0, 0)
}

/// Starts a local TCP service, so a client has something plausible to point at.
async fn start_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => {
                            if socket.write_all(&buf[..read]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// Runs the client against `frps` and gates its steady-state memory.
///
/// The cleanup is a guard rather than a tail of the function, so a failed
/// assertion does not leave an eight-megabyte process holding the fixture ports
/// for every later run to trip over.
async fn measure_under_budget(fixture: &Fixture, count: u16, budget: u64, what: &str) {
    let local_port = start_echo().await;
    let config_path = std::env::temp_dir().join(format!("rust-frpc-{count}.toml"));
    write_config(&config_path, count, local_port);

    let mut client = start_client(&fixture.frpc, &config_path, count).await;
    let reading = measure(&client).await;

    let verdict = if reading.gated() <= budget {
        Ok(())
    } else {
        Err(format!(
            "the {what} client's {} is {} kB, over the {budget} kB budget",
            Reading::GATED_LABEL,
            reading.gated(),
        ))
    };

    // Reported before the kill, so a failing run still prints its numbers.
    println!(
        "{what}: working set {} kB (peak {}), private {} kB; budget {budget} kB on {}",
        reading.ws,
        reading.ws_peak,
        reading.private,
        Reading::GATED_LABEL,
    );

    let _ = client.kill().await;
    let _ = std::fs::remove_file(&config_path);

    if let Err(message) = verdict {
        panic!("{message}");
    }
}

/// The idle budget: a client with a single proxy registered, carrying nothing.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN, FRPS_CONFIG and FRPC_BIN"]
async fn the_client_fits_the_idle_budget() {
    let Some(fixture) = fixture() else {
        return;
    };
    // Held for the whole test: the client is pointed at a `frps`, and killing the
    // server first would have the reconnect loop logging failures over the
    // measurement.
    let _frps = start_frps(&fixture.bin, &fixture.config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let budget = budget("FRPC_RSS_BUDGET_KB", IDLE_BUDGET_KB);
    measure_under_budget(&fixture, 1, budget, "idle").await;
}
/// The hundred-proxy budget.
#[tokio::test]
#[ignore = "needs a real frps: set RUN_REAL_FRPS_TESTS=1, FRPS_BIN, FRPS_CONFIG and FRPC_BIN"]
async fn the_client_fits_the_budget_with_a_hundred_proxies() {
    let Some(fixture) = fixture() else {
        return;
    };
    let _frps = start_frps(&fixture.bin, &fixture.config_path);
    wait_for_port(CONTROL_PORT, Duration::from_secs(10)).await;

    let budget = budget("FRPC_RSS_100_BUDGET_KB", HUNDRED_BUDGET_KB);
    measure_under_budget(&fixture, 100, budget, "100 proxies").await;
}
