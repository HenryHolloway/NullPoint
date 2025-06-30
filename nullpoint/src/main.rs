use clap::{Arg, Command as ClapCommand};
use libc;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::ToSocketAddrs;
use std::process::Command;

// ---------- Constants -------------------------------------------------------
const TABLE_NAME: &str = "nullpoint";
const CHAIN_NAME: &str = "rustables_block";
const CHAIN_PRIORITY: &str = "-100"; // run *before* iptables-compat chains
const SET_V4_NAME: &str = "blocked4";
const SET_V6_NAME: &str = "blocked6";

const BLOCKED_DOMAINS_PATH: &str = "/var/lib/NullPoint/blocked_domains";
const NFTABLES_CONFIG_PATH: &str = "/etc/nftables.conf";
// ---------------------------------------------------------------------------

fn main() {
    if !is_root() {
        eprintln!("This program must be run as root.");
        std::process::exit(1);
    }

    let matches = setup_cli();

    if matches.subcommand_matches("monitor").is_some() {
        run_monitoring_service();
    } else {
        setup_nftables();

        match matches.subcommand() {
            Some(("block", m)) => {
                block_domain(m.get_one::<String>("DOMAIN").unwrap());
                save_nftables_config();
            }
            Some(("unblock", m)) => {
                unblock_domain(m.get_one::<String>("DOMAIN").unwrap());
                save_nftables_config();
            }
            Some(("list", _)) => list_blocked_domains(),
            _ => {}
        }
    }
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

// ----------------------- CLI ------------------------------------------------
fn setup_cli() -> clap::ArgMatches {
    ClapCommand::new("Nullpoint")
        .version("0.1")
        .author("NullPoint")
        .about("Rust-powered distraction blocker with nftables")
        .subcommand(
            ClapCommand::new("block")
                .about("Block a domain")
                .arg(Arg::new("DOMAIN").help("Domain to block").required(true)),
        )
        .subcommand(
            ClapCommand::new("unblock")
                .about("Unblock a domain")
                .arg(Arg::new("DOMAIN").help("Domain to unblock").required(true)),
        )
        .subcommand(ClapCommand::new("list").about("List currently blocked domains"))
        .subcommand(ClapCommand::new("monitor").about("Run background monitor"))
        .get_matches()
}

// --------------------- Nftables bootstrap ----------------------------------
fn setup_nftables() {
    if !check_table_exists() {
        run_nft(&["add", "table", "inet", TABLE_NAME]);
    }

    if !check_chain_exists() {
        run_nft(&[
            "add",
            "chain",
            "inet",
            TABLE_NAME,
            CHAIN_NAME,
            "{",
            "type",
            "filter",
            "hook",
            "output",
            "priority",
            CHAIN_PRIORITY,
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ]);
    }

    if !check_set_exists(SET_V4_NAME) {
        create_set(SET_V4_NAME, "ipv4_addr");
    }
    if !check_set_exists(SET_V6_NAME) {
        create_set(SET_V6_NAME, "ipv6_addr");
    }

    ensure_block_rules();
}

fn check_table_exists() -> bool {
    Command::new("nft")
        .args(&["list", "table", "inet", TABLE_NAME])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn check_chain_exists() -> bool {
    Command::new("nft")
        .args(&["list", "chain", "inet", TABLE_NAME, CHAIN_NAME])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn check_set_exists(set: &str) -> bool {
    Command::new("nft")
        .args(&["list", "set", "inet", TABLE_NAME, set])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn create_set(name: &str, ty: &str) {
    run_nft(&[
        "add",
        "set",
        "inet",
        TABLE_NAME,
        name,
        "{",
        "type",
        ty,
        ";",
        "flags",
        "interval",
        ";",
        "}",
    ]);
}

// Insert drop rules unconditionally; duplicates are ignored.
fn ensure_block_rules() {
    add_drop_rule("ip", SET_V4_NAME);
    add_drop_rule("ip6", SET_V6_NAME);
}

fn add_drop_rule(proto: &str, set_name: &str) {
    let status = Command::new("nft")
        .args(&[
            "add",
            "rule",
            "inet",
            TABLE_NAME,
            CHAIN_NAME,
            proto,
            "daddr",
            &format!("@{set_name}"),
            "drop",
        ])
        .status();
    if let Ok(s) = status {
        if !s.success() && s.code() != Some(1) {
            eprintln!("Failed to add {proto} drop rule (exit {code:?})", code = s.code());
        }
    }
}

// ---------------- Domain handling ------------------------------------------
fn block_domain(domain_raw: &str) {
    let domain = domain_raw
        .trim_start_matches("http://")
        .trim_start_matches("https://");

    if let Err(e) = validate_domain(domain) {
        eprintln!("{e}");
        return;
    }

    println!("Blocking domain: {domain}");

    persist_domain(domain);

    // Resolve and populate the sets
    let base = domain.trim_start_matches("*.");
    if let Ok(addrs) = format!("{base}:0").to_socket_addrs() {
        for a in addrs {
            match a {
                std::net::SocketAddr::V4(v4) => add_to_set(SET_V4_NAME, &v4.ip().to_string()),
                std::net::SocketAddr::V6(v6) => add_to_set(SET_V6_NAME, &v6.ip().to_string()),
            }
        }
    } else {
        eprintln!("Failed to resolve {base}");
    }
}

fn validate_domain(d: &str) -> Result<(), String> {
    if d.is_empty() {
        return Err("Domain cannot be empty.".into());
    }
    if d.contains(' ') {
        return Err("Domain cannot contain spaces.".into());
    }
    if !d.contains('.') {
        return Err("Domain must contain at least one dot.".into());
    }
    let bad = ['/', '\\', ':', '*', '?', '"', '<', '>', '|'];
    if d.chars().any(|c| bad.contains(&c)) {
        return Err("Domain contains invalid characters.".into());
    }
    if d.len() > 253 {
        return Err("Domain is too long (max 253 chars).".into());
    }
    for label in d.split('.') {
        if label.len() > 63 {
            return Err(format!("Label '{label}' is too long (max 63 chars)"));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(format!("Invalid label '{label}'"));
        }
    }
    Ok(())
}

fn persist_domain(domain: &str) {
    let existing = std::fs::read_to_string(BLOCKED_DOMAINS_PATH).unwrap_or_default();
    if existing.lines().any(|l| l == domain) {
        return;
    }
    if let Ok(mut f) = OpenOptions::new()
        .append(true)
        .create(true)
        .open(BLOCKED_DOMAINS_PATH)
    {
        let _ = writeln!(f, "{domain}");
    }
}

fn add_to_set(set: &str, ip: &str) {
    let status = Command::new("nft")
        .args(&[
            "add",
            "element",
            "inet",
            TABLE_NAME,
            set,
            "{",
            ip,
            "}",
        ])
        .status();
    if let Ok(s) = status {
        if s.success() {
            println!("Added {ip} to {set}");
        }
    }
}

fn unblock_domain(domain: &str) {
    println!("Unblocking {domain}");

    countdown();

    if domain == "all" {
        run_nft(&["flush", "set", "inet", TABLE_NAME, SET_V4_NAME]);
        run_nft(&["flush", "set", "inet", TABLE_NAME, SET_V6_NAME]);
        if let Ok(mut f) = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(BLOCKED_DOMAINS_PATH)
        {
            let _ = writeln!(f);
        }
        return;
    }

    // Remove IPs from sets
    if let Ok(addrs) = format!("{domain}:0").to_socket_addrs() {
        for a in addrs {
            match a {
                std::net::SocketAddr::V4(v4) => {
                    run_nft(&[
                        "delete",
                        "element",
                        "inet",
                        TABLE_NAME,
                        SET_V4_NAME,
                        "{",
                        &v4.ip().to_string(),
                        "}",
                    ]);
                }
                std::net::SocketAddr::V6(v6) => {
                    run_nft(&[
                        "delete",
                        "element",
                        "inet",
                        TABLE_NAME,
                        SET_V6_NAME,
                        "{",
                        &v6.ip().to_string(),
                        "}",
                    ]);
                }
            }
        }
    }

    // Remove from file
    if let Ok(file) = File::open(BLOCKED_DOMAINS_PATH) {
        let lines: Vec<String> = BufReader::new(file)
            .lines()
            .flatten()
            .filter(|l| l != domain)
            .collect();
        if let Ok(mut f) = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(BLOCKED_DOMAINS_PATH)
        {
            for l in lines {
                let _ = writeln!(f, "{l}");
            }
        }
    }
}

fn countdown() {
    let mins: u64 = 60;
    let len = 50;
    for m in 0..=mins {
        let frac = m as f64 / mins as f64;
        let filled = (frac * len as f64).round() as usize;
        print!(
            "\r[{}{}] {:3.0}% ({} min)",
            "#".repeat(filled),
            " ".repeat(len - filled),
            frac * 100.0,
            m
        );
        let _ = std::io::stdout().flush();
        if m < mins {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }
    println!("\nCountdown complete.");
}

// ----------------------- Utilities -----------------------------------------
fn run_nft(args: &[&str]) {
    if let Err(e) = Command::new("nft").args(args).status() {
        eprintln!("Error running nft {args:?}: {e}");
    }
}

fn list_blocked_domains() {
    println!("nftables chain '{CHAIN_NAME}':");
    let _ = Command::new("nft")
        .args(&["list", "chain", "inet", TABLE_NAME, CHAIN_NAME])
        .status();

    if let Ok(file) = File::open(BLOCKED_DOMAINS_PATH) {
        println!("\nBlocked domains:");
        for d in BufReader::new(file).lines().flatten() {
            if !d.trim().is_empty() {
                println!("• {d}");
            }
        }
    }
}

fn monitor_blocked_domains_file() {
    setup_nftables(); // ensure infra exists
    run_nft(&["flush", "set", "inet", TABLE_NAME, SET_V4_NAME]);
    run_nft(&["flush", "set", "inet", TABLE_NAME, SET_V6_NAME]);

    if let Ok(file) = File::open(BLOCKED_DOMAINS_PATH) {
        for domain in BufReader::new(file).lines().flatten() {
            if let Ok(addrs) = format!("{domain}:0").to_socket_addrs() {
                for a in addrs {
                    match a {
                        std::net::SocketAddr::V4(v4) => {
                            add_to_set(SET_V4_NAME, &v4.ip().to_string())
                        }
                        std::net::SocketAddr::V6(v6) => {
                            add_to_set(SET_V6_NAME, &v6.ip().to_string())
                        }
                    }
                }
            }
        }
    }
}

fn save_nftables_config() {
    if let Ok(out) = Command::new("nft").args(&["list", "ruleset"]).output() {
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(NFTABLES_CONFIG_PATH)
        {
            let _ = f.write_all(&out.stdout);
            println!("nftables configuration saved.");
        }
    }
}

fn run_monitoring_service() {
    std::thread::spawn(|| loop {
        monitor_blocked_domains_file();
        std::thread::sleep(std::time::Duration::from_secs(60));
    })
    .join()
    .expect("monitor thread failed");
}