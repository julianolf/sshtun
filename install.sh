#!/usr/bin/env bash

set -euo pipefail

src=https://raw.githubusercontent.com/julianolf/sshtun/refs/heads/main/sshtun.sh
dst=/usr/local/bin/sshtun

sudo -v
sudo curl -sSfL --output "$dst" "$src"
sudo chmod +x "$dst"
