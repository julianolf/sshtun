#!/usr/bin/env bash

set -e

CONFIG="$HOME/.config/sshacky/config.cfg"
DOMAINS="$HOME/.config/sshacky/domains"
INTERFACE_IP="198.18.0.1"
INTERFACE_NAME="utun123"
SOCKS_PORT="1080"
SSH_HOST=""
SHOW_HELP=0
SHOW_VERSION=0
VERSION="0.1.0"

parse_args() {
	while [ $# -gt 0 ]; do
		case "$1" in
		--config)
			CONFIG="$2"
			shift 2
			;;
		--domains)
			DOMAINS="$2"
			shift 2
			;;
		--interface-ip)
			INTERFACE_IP="$2"
			shift 2
			;;
		--interface-name)
			INTERFACE_NAME="$2"
			shift 2
			;;
		--socks-port)
			SOCKS_PORT="$2"
			shift 2
			;;
		--ssh-host)
			SSH_HOST="$2"
			shift 2
			;;
		--help)
			SHOW_HELP=1
			shift
			;;
		--version)
			SHOW_VERSION=1
			shift
			;;
		*)
			echo "Unknown option: $1"
			exit 1
			;;
		esac
	done
}

load_config() {
	if [ -f "$CONFIG" ] && [ -r "$CONFIG" ]; then
		# shellcheck source=/dev/null
		source "$CONFIG"
	fi
}

show_usage() {
	cat <<EOF
Usage: sshacky [options...]

 --config               Configuration file (default: ~/.config/sshacky/config.cfg)
 --domains              File containing a list of domains (default: ~/.config/sshacky/domains)
 --help                 Show usage and exit
 --interface-ip         IP address for the TUN interface (default: 198.18.0.1)
 --interface-name       TUN interface name (default: utun123)
 --socks-port           Port for the SSH tunnel (default: 1080)
 --ssh-host             User and host to create the SSH tunnel (e.g., user@jumpbox)
 --version              Show version and exit
EOF
}

show_version() {
	echo "$0 v$VERSION"
}

main() {
	parse_args "$@"

	if [ "$SHOW_HELP" -eq 1 ]; then
		show_usage
		exit 0
	fi

	if [ "$SHOW_VERSION" -eq 1 ]; then
		show_version "$0"
		exit 0
	fi

	load_config

	if [ ! -f "$DOMAINS" ] || [ ! -r "$DOMAINS" ]; then
		echo "error: '$DOMAINS' is either not a regular file or not readable"
		exit 1
	fi
}

main "$@"
