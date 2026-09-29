//! `frpc reload|status|stop`: managing a running client through its admin API.
//!
//! The three commands are the same shape — load the config to learn where the
//! admin API is, call it, report what happened — so they share one entry point.
//! The Go client does this with a `clientsdk` package; here it is
//! [`crate::client::sdk`].
//!
//! The address comes from the config file rather than from a flag, which is the
//! Go behaviour and a good one: the operator already has to say which client they
//! mean, and the file is what identifies it.

use std::process::ExitCode;

use crate::cli::{AdminAction, AdminArgs};
use crate::client::sdk::{AdminClient, Reply};
use crate::config;

/// Runs an admin subcommand.
pub fn run(args: &AdminArgs) -> ExitCode {
    let loaded = match config::load_file_with(&args.config, strictness(args)) {
        Ok(loaded) => loaded,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    // `complete()` always leaves one behind, but a client that never called it
    // would have nothing to talk to, so this is handled rather than unwrapped.
    let Some(web) = loaded.config.common.web_server.as_ref() else {
        eprintln!(
            "error: webServer is not configured in {}",
            args.config.display()
        );
        return ExitCode::from(1);
    };

    // The Go client refuses the same way, and for the same reason: without a port
    // there is nothing listening, so there is nothing to talk to.
    if web.port == 0 {
        eprintln!(
            "error: web server port should be set if you want to use this feature \
             (webServer.port in {})",
            args.config.display()
        );
        return ExitCode::from(1);
    }

    let timeout = args.api_timeout.map(std::time::Duration::from_secs);
    let client = AdminClient::new(&web.addr, web.port, &web.user, &web.password, timeout);

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("error: build runtime: {err}");
            return ExitCode::from(2);
        }
    };

    let result = runtime.block_on(async {
        match args.action {
            AdminAction::Reload => client.reload(args.strict_config).await,
            AdminAction::Status => client.status().await,
            AdminAction::Stop => client.stop().await,
        }
    });

    let reply = match result {
        Ok(reply) => reply,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(1);
        }
    };

    if !reply.is_ok() {
        eprintln!("error: {}", reply.error_message());
        return ExitCode::from(1);
    }

    match args.action {
        AdminAction::Reload => println!("reload success"),
        AdminAction::Stop => println!("stop success"),
        AdminAction::Status => print_status(&reply),
    }
    ExitCode::SUCCESS
}

fn strictness(args: &AdminArgs) -> config::Strictness {
    if args.strict_config {
        config::Strictness::Strict
    } else {
        config::Strictness::Lenient
    }
}

/// Prints `/api/status` the way `frpc status` does: one table per proxy type.
///
/// The column headers and their order match the Go client, because the output is
/// something operators read side by side and a different order would be a
/// needless difference.
fn print_status(reply: &Reply) {
    let by_type: std::collections::BTreeMap<String, Vec<ProxyStatusOut>> =
        match serde_json::from_str(&reply.body) {
            Ok(status) => status,
            Err(err) => {
                eprintln!("error: could not read the status response: {err}");
                eprintln!("{}", reply.body);
                return;
            }
        };

    println!("Proxy Status...\n");
    for (proxy_type, proxies) in &by_type {
        if proxies.is_empty() {
            continue;
        }
        println!("{}", proxy_type.to_uppercase());

        let rows: Vec<[&str; 6]> = proxies
            .iter()
            .map(|proxy| {
                [
                    proxy.name.as_str(),
                    proxy.status.as_str(),
                    proxy.local_addr.as_str(),
                    proxy.plugin.as_str(),
                    proxy.remote_addr.as_str(),
                    proxy.err.as_str(),
                ]
            })
            .collect();
        print_table(
            &[
                "Name",
                "Status",
                "LocalAddr",
                "Plugin",
                "RemoteAddr",
                "Error",
            ],
            &rows,
        );
        println!();
    }
}

/// The subset of the status response the table needs.
#[derive(serde::Deserialize)]
struct ProxyStatusOut {
    name: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    local_addr: String,
    #[serde(default)]
    plugin: String,
    #[serde(default)]
    remote_addr: String,
    #[serde(default)]
    err: String,
}

/// A left-aligned text table, like the one `frpc status` prints.
///
/// Hand-rolled rather than pulled in as a dependency: it is thirty lines, and the
/// binary's size is the point of the exercise.
fn print_table(headers: &[&str], rows: &[[&str; 6]]) {
    let mut widths: Vec<usize> = headers.iter().map(|header| header.len()).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }

    let separator: Vec<String> = widths.iter().map(|width| "-".repeat(width + 2)).collect();
    let line = |cells: Vec<String>| {
        let padded: Vec<String> = cells
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!(" {cell:<width$} "))
            .collect();
        println!("|{}|", padded.join("|"));
    };

    line(headers.iter().map(|header| header.to_string()).collect());
    println!("+{}+", separator.join("+"));
    for row in rows {
        line(row.iter().map(|cell| cell.to_string()).collect());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_status_table_lines_up() {
        // The widths are driven by the widest cell, so a short header and a long
        // value still produce a readable table.
        let rows = [["ssh", "running", "127.0.0.1:22", "", "example.com:6000", ""]];
        print_table(
            &[
                "Name",
                "Status",
                "LocalAddr",
                "Plugin",
                "RemoteAddr",
                "Error",
            ],
            &rows,
        );
    }

    #[test]
    fn a_status_response_parses_into_the_columns() {
        let body = r#"{"tcp":[{"name":"ssh","type":"tcp","status":"running",
            "err":"","local_addr":"127.0.0.1:22","plugin":"","remote_addr":"example.com:6000"}]}"#;
        let by_type: std::collections::BTreeMap<String, Vec<ProxyStatusOut>> =
            serde_json::from_str(body).unwrap();
        let tcp = &by_type["tcp"];
        assert_eq!(tcp.len(), 1);
        assert_eq!(tcp[0].name, "ssh");
        assert_eq!(tcp[0].remote_addr, "example.com:6000");
    }
}
