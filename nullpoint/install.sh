#!/bin/bash


cargo build --release

sudo mkdir -p /var/lib/NullPoint
sudo touch /var/lib/NullPoint/blocked_domains
sudo chmod 666 /var/lib/NullPoint/blocked_domains

if [ -f "/etc/systemd/system/nullpoint.service" ]; then
  if sudo systemctl is-active --quiet nullpoint; then
    sudo systemctl stop nullpoint
  fi
  sudo cp ./target/release/nullpoint /usr/local/bin/nullpoint
  sudo systemctl daemon-reload
  sudo systemctl start nullpoint
else
  sudo cp ./target/release/nullpoint /usr/local/bin/nullpoint
  sudo bash -c 'cat > /etc/systemd/system/nullpoint.service <<EOF
[Unit]
Description=Nullpoint Service
After=network.target

[Service]
ExecStart=/usr/local/bin/nullpoint monitor
Restart=always

[Install]
WantedBy=multi-user.target
EOF'
  sudo systemctl daemon-reload
  sudo systemctl enable nullpoint
  sudo systemctl start nullpoint
fi
