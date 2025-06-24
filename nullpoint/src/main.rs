use clap::{Arg, Command as ClapCommand};
use std::process::Command;
use std::net::ToSocketAddrs;
use std::io::{self, Write};
use std::fs::{OpenOptions, File};
use std::io::{BufReader, BufRead};
use libc;

const TABLE_NAME: &str = "nullpoint";
const CHAIN_NAME: &str = "rustables_block";
const SET_V4_NAME: &str = "blocked4";
const SET_V6_NAME: &str = "blocked6";
const BLOCKED_DOMAINS_PATH: &str = "/var/lib/NullPoint/blocked_domains";
const NFTABLES_CONFIG_PATH: &str = "/etc/nftables.conf";

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

        if let Some(matches) = matches.subcommand_matches("block") {
            let domain = matches.get_one::<String>("DOMAIN").unwrap();
            block_domain(domain);
            save_nftables_config();
        } else if let Some(matches) = matches.subcommand_matches("unblock") {
            let domain = matches.get_one::<String>("DOMAIN").unwrap();
            unblock_domain(domain);
            save_nftables_config();
        } else if matches.subcommand_matches("list").is_some() {
            list_blocked_domains();
        }
    }
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn run_monitoring_service() {
    std::thread::spawn(move || {
        loop {
            monitor_blocked_domains_file();
            std::thread::sleep(std::time::Duration::from_secs(60)); // Check every 60 seconds
        }
    }).join().expect("Failed to join monitoring thread");
}

fn setup_cli() -> clap::ArgMatches {
    ClapCommand::new("Nullpoint")
        .version("0.1")
        .author("Your Name <your@email.com>")
        .about("Rust-powered distraction blocker with nftables!")
        .subcommand(ClapCommand::new("block")
            .about("Block a domain")
            .arg(Arg::new("DOMAIN")
                .help("The domain to block")
                .required(true)))
        .subcommand(ClapCommand::new("unblock")
            .about("Unblock a domain")
            .arg(Arg::new("DOMAIN")
                .help("The domain to unblock")
                .required(true)))
        .subcommand(ClapCommand::new("list")
            .about("List currently blocked domains"))
        .subcommand(ClapCommand::new("monitor")
            .about("Run the monitoring service"))
        .get_matches()
}

fn setup_nftables() {
    if !check_table_exists() {
        create_table();
    }

    if !check_chain_exists() {
        create_chain();
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
    let table_check = Command::new("nft")
        .args(&["list", "table", "inet", TABLE_NAME])
        .output();

    table_check.is_ok() && table_check.unwrap().status.success()
}

fn create_table() {
    println!("Creating nftables table '{}'", TABLE_NAME);
    Command::new("nft")
        .args(&["add", "table", "inet", TABLE_NAME])
        .status()
        .expect("Failed to create nftables table!");
}

fn check_chain_exists() -> bool {
    let chain_check = Command::new("nft")
        .args(&["list", "chain", "inet", TABLE_NAME, CHAIN_NAME])
        .output();

    chain_check.is_ok() && chain_check.unwrap().status.success()
}

fn create_chain() {
    println!("Creating nftables chain '{}'", CHAIN_NAME);
    Command::new("nft")
        .args(&[
            "add", "chain", "inet", TABLE_NAME, CHAIN_NAME,
            "{", "type", "filter", "hook", "output", "priority", "0", ";", "}",
        ])
        .status()
        .expect("Failed to create nftables chain!");
}

fn check_set_exists(set: &str) -> bool {
    Command::new("nft")
        .args(&["list", "set", "inet", TABLE_NAME, set])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn create_set(set: &str, ty: &str) {
    println!("Creating set '{}'", set);
    Command::new("nft")
        .args(&[
            "add", "set", "inet", TABLE_NAME, set,
            "{", "type", ty, ";", "flags", "interval", ";", "}",
        ])
        .status()
        .expect("Failed to create nftables set");
}

fn ensure_block_rules() {
    // `nft list chain` so we can inspect the current rules
    let list_output = Command::new("nft")
        .args(&["list", "chain", "inet", TABLE_NAME, CHAIN_NAME])
        .output();

    if let Ok(output) = list_output {
        let stdout = String::from_utf8_lossy(&output.stdout);

        // IPv4 rule
        if !stdout.contains(&format!("ip  daddr @{} drop", SET_V4_NAME))
            && !stdout.contains(&format!("ip daddr @{} drop", SET_V4_NAME))
        {
            println!("Adding IPv4 drop rule to '{}'", CHAIN_NAME);
            Command::new("nft")
                .args(&[
                    "add", "rule", "inet", TABLE_NAME, CHAIN_NAME,
                    "ip", "daddr", &format!("@{}", SET_V4_NAME), "drop",
                ])
                .status()
                .expect("Failed to add IPv4 drop rule");
        }

        // IPv6 rule
        if !stdout.contains(&format!("ip6 daddr @{} drop", SET_V6_NAME)) {
            println!("Adding IPv6 drop rule to '{}'", CHAIN_NAME);
            Command::new("nft")
                .args(&[
                    "add", "rule", "inet", TABLE_NAME, CHAIN_NAME,
                    "ip6", "daddr", &format!("@{}", SET_V6_NAME), "drop",
                ])
                .status()
                .expect("Failed to add IPv6 drop rule");
        }
    } else {
        eprintln!(
            "Could not list chain '{}'; block rules may be missing.",
            CHAIN_NAME
        );
    }
}

fn block_domain(domain: &str) {
    // Remove http:// or https:// from the domain if present
    let domain = domain.trim_start_matches("http://").trim_start_matches("https://");
    
    // Validate the domain format
    if domain.is_empty() {
        eprintln!("Domain cannot be empty.");
        return;
    }

    if domain.contains(' ') {
        eprintln!("Domain cannot contain spaces.");
        return;
    }

    if !domain.contains('.') {
        eprintln!("Invalid domain format: '{}'. A domain must contain at least one dot.", domain);
        return;
    }

    // Check for invalid characters
    let invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|'];
    if domain.chars().any(|c| invalid_chars.contains(&c)) {
        eprintln!("Domain contains invalid characters.");
        return;
    }

    // Check if the domain is too long
    if domain.len() > 253 {
        eprintln!("Domain is too long. Maximum length is 253 characters.");
        return;
    }

    // Check if each label in the domain is valid
    for label in domain.split('.') {
        if label.len() > 63 {
            eprintln!("Domain label '{}' is too long. Maximum length for each label is 63 characters.", label);
            return;
        }
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') || label.starts_with('-') || label.ends_with('-') {
            eprintln!("Domain label '{}' is invalid. Labels must be alphanumeric and cannot start or end with a hyphen.", label);
            return;
        }
    }

    println!("Blocking domain: {}", domain);

    // Check if the domain is already in the file
    let file_content = std::fs::read_to_string(BLOCKED_DOMAINS_PATH)
        .unwrap_or_else(|_| String::new());

    if !file_content.lines().any(|line| line == domain) {
        // Save the domain to a file if it's not already present
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(BLOCKED_DOMAINS_PATH)
            .expect("Failed to open blocked_domains");
        writeln!(file, "{}", domain).expect("Failed to write domain to file");
    } else {
        println!("Domain '{}' is already blocked.", domain);
    }

    // Check if the domain is a wildcard
    let is_wildcard = domain.starts_with("*.");
    let base_domain = if is_wildcard {
        &domain[2..] // Remove the "*." part
    } else {
        domain
    };

    // Resolve base domain to IP addresses and add to the appropriate set
    if let Ok(addresses) = format!("{}:0", base_domain).to_socket_addrs() {
        for addr in addresses {
            match addr {
                std::net::SocketAddr::V4(ipv4_addr) => {
                    let ip_str = ipv4_addr.ip().to_string();
                    let _ = Command::new("nft")
                        .args(&[
                            "add", "element", "inet", TABLE_NAME, SET_V4_NAME,
                            "{", &ip_str, "}",
                        ])
                        .status();
                    println!("Blocked IPv4 {}", ip_str);
                }
                std::net::SocketAddr::V6(ipv6_addr) => {
                    let ip_str = ipv6_addr.ip().to_string();
                    let _ = Command::new("nft")
                        .args(&[
                            "add", "element", "inet", TABLE_NAME, SET_V6_NAME,
                            "{", &ip_str, "}",
                        ])
                        .status();
                    println!("Blocked IPv6 {}", ip_str);
                }
            }
        }
    } else {
        eprintln!("Failed to resolve domain: {}", base_domain);
    }
}

fn unblock_domain(domain: &str) {
    println!("Unblocking domain: {}", domain);
    
    // Countdown before unblocking
    println!("Please wait for a 60-minute countdown before the domain is unblocked.");
    let total_minutes: u64 = 60;
    let progress_bar_length: usize = 50;
    for elapsed in 0..=total_minutes {
        let fraction = elapsed as f64 / total_minutes as f64;
        let filled_length = (fraction * progress_bar_length as f64).round() as usize;
        let bar = format!("[{}{}]", "#".repeat(filled_length), " ".repeat(progress_bar_length - filled_length));
        print!("\r{} {:3.0}% ({} min elapsed)", bar, fraction * 100.0, elapsed);
        std::io::stdout().flush().expect("Failed to flush stdout");
        if elapsed < total_minutes {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }
    println!("\nCountdown complete. Proceeding with unblocking.");

    if domain == "all" {
        // --- CHANGED: flush both sets instead of deleting rules -----------
        let _ = Command::new("nft")
            .args(&["flush", "set", "inet", TABLE_NAME, SET_V4_NAME])
            .status();
        let _ = Command::new("nft")
            .args(&["flush", "set", "inet", TABLE_NAME, SET_V6_NAME])
            .status();

        // Clear the blocked_domains file
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(BLOCKED_DOMAINS_PATH)
            .expect("Failed to open blocked_domains for writing");
        writeln!(file, "").expect("Failed to clear blocked_domains file");
    } else {
        // Resolve domain to IP addresses and remove from the appropriate set
        if let Ok(addresses) = format!("{}:0", domain).to_socket_addrs() {
            for addr in addresses {
                match addr {
                    std::net::SocketAddr::V4(ipv4_addr) => {
                        let ip_str = ipv4_addr.ip().to_string();
                        let _ = Command::new("nft")
                            .args(&[
                                "delete", "element", "inet", TABLE_NAME, SET_V4_NAME,
                                "{", &ip_str, "}",
                            ])
                            .status();
                    }
                    std::net::SocketAddr::V6(ipv6_addr) => {
                        let ip_str = ipv6_addr.ip().to_string();
                        let _ = Command::new("nft")
                            .args(&[
                                "delete", "element", "inet", TABLE_NAME, SET_V6_NAME,
                                "{", &ip_str, "}",
                            ])
                            .status();
                    }
                }
            }
        } else {
            eprintln!("Failed to resolve domain: {}", domain);
        }

        // Remove the domain from the blocked_domains file
        let file = File::open(BLOCKED_DOMAINS_PATH);
        if let Ok(file) = file {
            let reader = BufReader::new(file);
            let lines: Vec<String> = reader.lines()
                .filter_map(Result::ok)
                .filter(|line| line != domain)
                .collect();

            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(BLOCKED_DOMAINS_PATH)
                .expect("Failed to open blocked_domains for writing");

            for line in lines {
                writeln!(file, "{}", line).expect("Failed to write domain to file");
            }
        } else {
            eprintln!("Failed to open blocked_domains.");
        }
    }
}

fn list_blocked_domains() {
    println!("Listing nftables rules and blocked domains...");

    // List current nftables rules
    let list_result = Command::new("nft")
        .args(&["list", "chain", "inet", TABLE_NAME, CHAIN_NAME])
        .output();

    if let Ok(output) = list_result {
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("Current nftables rules:\n{}", stdout);
    } else {
        eprintln!("Failed to list nftables rules.");
    }

    // Read the domain names from the file
    if let Ok(file) = File::open(BLOCKED_DOMAINS_PATH) {
        let reader = BufReader::new(file);
        let domains: Vec<String> = reader.lines()
            .filter_map(Result::ok)
            .collect();

        println!("Blocked domains:");

        if domains.is_empty() || (domains.len() == 1 && domains[0].trim().is_empty()) {
            println!("No domains are currently blocked");
        } else {
            for domain in domains {
                if !domain.trim().is_empty() {
                    println!("Blocked Domain: {}", domain);
                }
            }
        }
    } else {
        eprintln!("Failed to open blocked_domains.");
    }
}

fn monitor_blocked_domains_file() {
    let table_ok = Command::new("nft")
        .args(&["list", "table", "inet", TABLE_NAME])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !table_ok {
        let _ = Command::new("nft")
            .args(&["add", "table", "inet", TABLE_NAME])
            .status();
    }

    let chain_ok = Command::new("nft")
        .args(&["list", "chain", "inet", TABLE_NAME, CHAIN_NAME])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !chain_ok {
        let _ = Command::new("nft")
            .args(&[
                "add", "chain", "inet", TABLE_NAME, CHAIN_NAME,
                "{", "type", "filter", "hook", "output", "priority", "0", ";", "}",
            ])
            .status();
    }

    if !check_set_exists(SET_V4_NAME) {
        create_set(SET_V4_NAME, "ipv4_addr");
    }
    if !check_set_exists(SET_V6_NAME) {
        create_set(SET_V6_NAME, "ipv6_addr");
    }

    let _ = Command::new("nft")
        .args(&["flush", "set", "inet", TABLE_NAME, SET_V4_NAME])
        .status();
    let _ = Command::new("nft")
        .args(&["flush", "set", "inet", TABLE_NAME, SET_V6_NAME])
        .status();


    if let Ok(file) = File::open(BLOCKED_DOMAINS_PATH) {
        let reader = BufReader::new(file);
        for domain in reader.lines().flatten() {
            if let Ok(addresses) = format!("{}:0", domain).to_socket_addrs() {
                for addr in addresses {
                    match addr {
                        std::net::SocketAddr::V4(ipv4) => {
                            let ip = ipv4.ip().to_string();
                            let _ = Command::new("nft")
                                .args(&[
                                    "add", "element", "inet", TABLE_NAME, SET_V4_NAME,
                                    "{", &ip, "}",
                                ])
                                .status();
                        }
                        std::net::SocketAddr::V6(ipv6) => {
                            let ip = ipv6.ip().to_string();
                            let _ = Command::new("nft")
                                .args(&[
                                    "add", "element", "inet", TABLE_NAME, SET_V6_NAME,
                                    "{", &ip, "}",
                                ])
                                .status();
                        }
                    }
                }
            }
        }
    } else {
        eprintln!("Failed to open blocked_domains.");
    }
}

fn save_nftables_config() {
    println!("Saving nftables configuration to '{}'", NFTABLES_CONFIG_PATH);
    let result = Command::new("nft")
        .args(&["list", "ruleset"])
        .output();

    if let Ok(output) = result {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(NFTABLES_CONFIG_PATH)
            .expect("Failed to open nftables config file for writing");
        writeln!(file, "{}", stdout).expect("Failed to write nftables config to file");
        println!("Nftables configuration saved successfully.");
    } else {
        eprintln!("Failed to save nftables configuration.");
    }
}