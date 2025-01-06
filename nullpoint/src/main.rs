use clap::{Arg, Command as ClapCommand};
use std::process::Command;
use std::net::ToSocketAddrs;
use std::io::{self, Write};
use std::fs::{OpenOptions, File};
use std::io::{BufReader, BufRead};
use systemd::journal; // Add systemd journal for logging
use libc;

const TABLE_NAME: &str = "nullpoint";
const CHAIN_NAME: &str = "rustables_block";
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

    // Resolve base domain to IP addresses
    let addresses = format!("{}:0", base_domain).to_socket_addrs();

    if let Ok(addresses) = addresses {
        for addr in addresses {
            if let std::net::SocketAddr::V4(ipv4_addr) = addr {
                let ip = ipv4_addr.ip();
                // Use drop instead of redirect
                let rule = format!(
                    "add rule inet {} {} ip daddr {} drop",
                    TABLE_NAME, CHAIN_NAME, ip
                );
                let result = Command::new("nft")
                    .args(rule.split_whitespace())
                    .status();

                if let Ok(status) = result {
                    if status.success() {
                        println!("Successfully blocked IP: {}", ip);
                    } else {
                        eprintln!("Failed to block IP: {}. Status: {:?}", ip, status);
                    }
                } else {
                    eprintln!("Error executing nft command for IP: {}", ip);
                }
            }
        }
    } else {
        eprintln!("Failed to resolve domain: {}", base_domain);
    }
}

fn unblock_domain(domain: &str) {
    println!("Unblocking domain: {}", domain);

    if domain == "all" {
        // Unblock all domains
        let list_result = Command::new("nft")
            .args(&["-a", "list", "chain", "inet", TABLE_NAME, CHAIN_NAME])
            .output();

        match list_result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                println!("Current rules:\n{}", stdout); // Debugging output
                if !stderr.is_empty() {
                    eprintln!("Error listing rules: {}", stderr); // Capture any errors
                }

                for line in stdout.lines() {
                    if let Some(handle_pos) = line.find("handle") {
                        let handle = line[handle_pos + 7..].trim();
                        if handle.chars().all(char::is_numeric) {
                            println!("Found handle: {}", handle); // Debugging output

                            // Delete rule by handle
                            let delete_result = Command::new("nft")
                                .args(&[
                                    "delete", "rule", "inet", TABLE_NAME, CHAIN_NAME, "handle", handle,
                                ])
                                .status();

                            if delete_result.is_err() || !delete_result.unwrap().success() {
                                eprintln!("Failed to unblock rule with handle: {}", handle);
                            } else {
                                println!("Successfully unblocked rule with handle: {}", handle);
                            }
                        } else {
                            eprintln!("Failed to find numeric handle in rule: {}", line);
                        }
                    } else {
                        eprintln!("Failed to find handle in rule: {}", line);
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to execute nft command: {}", e);
            }
        }

        // Clear the blocked_domains file
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(BLOCKED_DOMAINS_PATH)
            .expect("Failed to open blocked_domains for writing");
        writeln!(file, "").expect("Failed to clear blocked_domains file");
    } else {
        // Resolve domain to IP addresses
        let addresses = format!("{}:0", domain).to_socket_addrs();

        if let Ok(addresses) = addresses {
            for addr in addresses {
                if let std::net::SocketAddr::V4(ipv4_addr) = addr {
                    let ip = ipv4_addr.ip();

                    // List rules with handles, correcting the argument order
                    let list_result = Command::new("nft")
                        .args(&["-a", "list", "chain", "inet", TABLE_NAME, CHAIN_NAME])
                        .output();

                    match list_result {
                        Ok(output) => {
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            println!("Current rules:\n{}", stdout); // Debugging output
                            if !stderr.is_empty() {
                                eprintln!("Error listing rules: {}", stderr); // Capture any errors
                            }

                            for line in stdout.lines() {
                                if line.contains(&format!("ip daddr {} drop", ip)) {
                                    println!("Found rule for IP: {}", ip); // Debugging output

                                    // Extract the handle, which is typically a number after "handle"
                                    if let Some(handle_pos) = line.find("handle") {
                                        let handle = line[handle_pos + 7..].trim();
                                        if handle.chars().all(char::is_numeric) {
                                            println!("Found handle: {}", handle); // Debugging output

                                            // Delete rule by handle
                                            let delete_result = Command::new("nft")
                                                .args(&[
                                                    "delete", "rule", "inet", TABLE_NAME, CHAIN_NAME, "handle", handle,
                                                ])
                                                .status();

                                            if delete_result.is_err() || !delete_result.unwrap().success() {
                                                eprintln!("Failed to unblock IP: {}", ip);
                                            } else {
                                                println!("Successfully unblocked IP: {}", ip);
                                            }
                                        } else {
                                            eprintln!("Failed to find numeric handle for IP: {}", ip);
                                        }
                                    } else {
                                        eprintln!("Failed to find handle for IP: {}", ip);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to execute nft command: {}", e);
                        }
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
    let file = File::open(BLOCKED_DOMAINS_PATH);
    if let Ok(file) = file {
        let reader = BufReader::new(file);
        let mut stdout = io::stdout();
        writeln!(stdout, "Blocked domains:").unwrap();
        for line in reader.lines() {
            if let Ok(domain) = line {
                writeln!(stdout, "Blocked Domain: {}", domain).unwrap();
            }
        }
    } else {
        eprintln!("Failed to open blocked_domains or no domains are blocked.");
    }
}

fn monitor_blocked_domains_file() {
    // Ensure the table and chain exist, create them if they don't
    let table_check = Command::new("nft")
        .args(&["list", "table", "inet", TABLE_NAME])
        .status();

    if table_check.is_err() || !table_check.unwrap().success() {
        let _ = Command::new("nft")
            .args(&["add", "table", "inet", TABLE_NAME])
            .status();
    }

    let chain_check = Command::new("nft")
        .args(&["list", "chain", "inet", TABLE_NAME, CHAIN_NAME])
        .status();

    if chain_check.is_err() || !chain_check.unwrap().success() {
        let _ = Command::new("nft")
            .args(&[
                "add", "chain", "inet", TABLE_NAME, CHAIN_NAME,
                "{", "type", "filter", "hook", "output", "priority", "0;", "}"
            ])
            .status();
    }

    let file = File::open(BLOCKED_DOMAINS_PATH);
    if let Ok(file) = file {
        let reader = BufReader::new(file);
        let domains: Vec<String> = reader.lines().filter_map(Result::ok).collect();

        // List current nftables rules
        let list_result = Command::new("nft")
            .args(&["list", "chain", "inet", TABLE_NAME, CHAIN_NAME])
            .output();

        if let Ok(output) = list_result {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for domain in domains {
                let addresses = format!("{}:0", domain).to_socket_addrs();
                if let Ok(addresses) = addresses {
                    for addr in addresses {
                        if let std::net::SocketAddr::V4(ipv4_addr) = addr {
                            let ip = ipv4_addr.ip();
                            if !stdout.contains(&format!("ip daddr {} drop", ip)) {
                                // Add missing rule
                                let rule = format!(
                                    "add rule inet {} {} ip daddr {} drop",
                                    TABLE_NAME, CHAIN_NAME, ip
                                );
                                let result = Command::new("nft")
                                    .args(rule.split_whitespace())
                                    .status();

                                if let Ok(status) = result {
                                    if status.success() {
                                        println!("Successfully added missing rule for IP: {}", ip);
                                    } else {
                                        eprintln!("Failed to add rule for IP: {}. Status: {:?}", ip, status);
                                    }
                                } else {
                                    eprintln!("Error executing nft command for IP: {}", ip);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            eprintln!("Failed to list nftables rules.");
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