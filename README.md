# sshacky

![CI](https://github.com/julianolf/sshacky/actions/workflows/ci.yml/badge.svg?event=push)

Configure network traffic routing over SSH using SOCKS5.

### Platforms

- macOS

### Requirements

- [jq](https://jqlang.org)
- [tun2socks](https://github.com/xjasonlyu/tun2socks)

## Installation

```sh
sudo curl \
    -sSfL \
    --output /usr/local/bin/sshacky \
    https://raw.githubusercontent.com/julianolf/sshacky/refs/heads/main/sshacky.sh &&
    sudo chmod +x /usr/local/bin/sshacky
```

## Usage

```sh
Usage: sshacky [options...] <start|stop>

 --config               Configuration file (default: ~/.config/sshacky/config.json)
 --domains              Comma-separated list of domains (e.g., one.com,two.com)
 --help                 Show usage and exit
 --interface-ip         IP address for the TUN interface (default: 198.18.0.1)
 --interface-name       TUN interface name (default: utun123)
 --socks-port           Port for the SSH tunnel (default: 1080)
 --ssh-host             User and host to create the SSH tunnel (e.g., user@jumpbox)
 --version              Show version and exit
```

#### Configuration file

The configuration file must be in JSON format. It defines the settings used by the program.

Example:

```json
{
  "interface_ip": "198.18.0.1",
  "interface_name": "utun123",
  "socks_port": 1080,
  "ssh_host": "user@jumpbox",
  "domains": [
    "one.com",
    "two.com"
  ]
}
```
