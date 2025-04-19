# sshacky

![CI](https://github.com/julianolf/sshacky/actions/workflows/ci.yml/badge.svg?event=push)

Configure network traffic routing over SSH using SOCKS5.

### Platforms

- macOS

### Requirements

- [tun2socks](https://github.com/xjasonlyu/tun2socks)

## Installation

```sh
sudo curl \
    -sSfL \
    --output '/usr/local/bin/sshacky' \
    https://raw.githubusercontent.com/julianolf/sshacky/refs/heads/main/sshacky.sh &&
    sudo chmod +x /usr/local/bin/sshacky
```

## Usage

```sh
Usage: sshacky [options...] <start|stop>

 --config               Configuration file (default: ~/.config/sshacky/config.cfg)
 --domains              File containing a list of domains (default: ~/.config/sshacky/domains)
 --help                 Show usage and exit
 --interface-ip         IP address for the TUN interface (default: 198.18.0.1)
 --interface-name       TUN interface name (default: utun123)
 --socks-port           Port for the SSH tunnel (default: 1080)
 --ssh-host             User and host to create the SSH tunnel (e.g., user@jumpbox)
 --version              Show version and exit
```

#### Configuration file

The configuration file uses `key=value` pairs, one per line. Keys match the command-line flags: they are written in uppercase, with the leading double dashes removed and remaining dashes replaced by underscores.

Example:

```sh
INTERFACE_IP=198.18.0.1
INTERFACE_NAME=utun123
SOCKS_PORT=1080
SSH_HOST=user@jumpbox
```

#### Domains file

The domains file is a plain text file containing full domain names, one per line.

Example:

```
private.zone
sub.domain.net
```
