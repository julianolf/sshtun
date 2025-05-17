#!/usr/bin/env bash

set -euo pipefail

src=https://raw.githubusercontent.com/julianolf/sshtun/main/sshtun.sh
dst=/usr/local/bin/sshtun

sudo -v
echo "Downloading sshtun..."
sudo curl -sSfL --output "$dst" "$src"
sudo chmod +x "$dst"
echo "Installation complete."
