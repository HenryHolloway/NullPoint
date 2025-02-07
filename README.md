<div align="center">
<img alt="NullPoint" src="[https://github.com/HenryHolloway/MythMaker/blob/main/assets/TheMythMaker.png](https://github.com/user-attachments/assets/a934292a-e31b-4242-a3e5-a847840ef948)" width="200">
</div>


# NullPoint

NullPoint is a Rust-powered distraction blocker that utilizes nftables to block access to specified domains. It's designed to help you stay focused by preventing access to distracting websites at the network level.

## Features

- **Block Domains**: Easily block specific domains or a list of domains.
- **Unblock Cooldown**: Remove domains from the blocklist after a 60-minute cooldown.
- **View Blocked Domains**: List all currently blocked domains.
- **Automatic Monitoring**: A systemd service keeps your nftables rules in sync with the blocklist.

## Prerequisites

- **Rust and Cargo**: Ensure you have Rust and Cargo installed. [Install Rust](https://www.rust-lang.org/tools/install).
- **nftables**: nftables should be installed and properly configured on your system.
- **Systemd**: Required for managing the monitoring service.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/NullPoint.git
   ```

2. **Navigate to the Project Directory**

   ```bash
   cd NullPoint/nullpoint
   ```

3. **Run the Install Script**

   ```bash
   sudo ./install.sh
   ```

   This script will:

   - Build the project in release mode.
   - Create necessary directories and files.
   - Install the `nullpoint` binary to `/usr/local/bin/`.
   - Set up and start the `nullpoint` systemd service.

## Usage

### Blocking a Domain

To block a domain:

```bash
sudo nullpoint block example.com
```

Replace `example.com` with the domain you wish to block.

### Unblocking a Domain

To unblock a specific domain:

```bash
sudo nullpoint unblock example.com
```

To unblock all domains:

```bash
sudo nullpoint unblock all
```

### Listing Blocked Domains

To list all currently blocked domains:

```bash
sudo nullpoint list
```

### Preset Blocklists

There's a script available to block some common distracting websites. Right now, it only blocks Reddit and alternate Reddit frontends:

```bash
./preset_blocklist.sh
```

This script will prompt you before blocking the sites.

### Monitoring Service

The monitoring service runs in the background, checking the blocklist every 60 seconds to ensure nftables rules are up to date.

## Uninstallation

To completely remove NullPoint from your system:

1. **Stop and Disable the Service**

   ```bash
   sudo systemctl stop nullpoint
   sudo systemctl disable nullpoint
   ```

2. **Remove Service File**

   ```bash
   sudo rm /etc/systemd/system/nullpoint.service
   sudo systemctl daemon-reload
   ```

3. **Unblock All Domains**

   ```bash
   sudo nullpoint unblock all
   ```

4. **Remove Binary and Data Files**

   ```bash
   sudo rm /usr/local/bin/nullpoint
   sudo rm -rf /var/lib/NullPoint
   ```


## Development

### Building from Source

To build the project without installing:

```bash
cargo build --release
```

The binary will be located in `./target/release/nullpoint`.

### Running Without Installation

You can run the binary directly for testing:

```bash
sudo ./target/release/nullpoint [command]
```

Replace `[command]` with the desired subcommand (`block`, `unblock`, `list`, `monitor`).

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the GPL v3 License.
