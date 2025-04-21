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
VERSION="0.2.0"
ACTION=""
LOG_FILE="/tmp/sshacky-$(date "+%Y%m%d").log"
KEEP_ALIVE_INTERVAL=30
KEEP_ALIVE_COUNT=3

show_usage() {
	cat <<EOF
Usage: sshacky [options...] <start|stop>

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
	echo "sshacky v$VERSION"
}

parse_args() {
	POS_ARGS=()

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
		-*)
			echo "Unknown option: $1"
			echo "Try '$0 --help' for more information"
			exit 1
			;;
		*)
			POS_ARGS+=("$1")
			shift
			;;
		esac
	done

	if [ "$SHOW_HELP" -eq 1 ]; then
		show_usage
		exit 0
	fi

	if [ "$SHOW_VERSION" -eq 1 ]; then
		show_version
		exit 0
	fi

	if [ "${#POS_ARGS[@]}" -eq 0 ]; then
		echo "Error: missing action argument"
		echo "Try '$0 --help' for more information"
		exit 1
	fi

	ACTION="${POS_ARGS[0]}"

	if [ "$ACTION" != "start" ] && [ "$ACTION" != "stop" ]; then
		echo "Error: invalid action '$ACTION'"
		echo "Try '$0 --help' for more information"
		exit 1
	fi
}

load_config() {
	if [ -f "$CONFIG" ] && [ -r "$CONFIG" ]; then
		# shellcheck source=/dev/null
		source "$CONFIG"
	fi
}

create_ssh_tunnel() {
	if [ -z "$SSH_HOST" ]; then
		echo "Error: missing SSH host"
		echo "Try '$0 --help' for more information"
		exit 1

	fi

	if ! pgrep -qf "ssh -fN -D $SOCKS_PORT"; then
		echo "[+] Starting SSH SOCKS5 proxy..."
		ssh -fNT -o ServerAliveInterval="$KEEP_ALIVE_INTERVAL" -o ServerAliveCountMax="$KEEP_ALIVE_COUNT" -D "$SOCKS_PORT" "$SSH_HOST"
		sleep 1
	else
		echo "[✓] SSH SOCKS proxy already running."
	fi
}

destroy_ssh_tunnel() {
	if pgrep -qf "ssh -fNT -o ServerAliveInterval=$KEEP_ALIVE_INTERVAL -o ServerAliveCountMax=$KEEP_ALIVE_COUNT -D $SOCKS_PORT $SSH_HOST"; then
		echo "[−] Killing SSH SOCKS tunnel on port $SOCKS_PORT..."
		pkill -f "ssh -fNT -o ServerAliveInterval=$KEEP_ALIVE_INTERVAL -o ServerAliveCountMax=$KEEP_ALIVE_COUNT -D $SOCKS_PORT $SSH_HOST"
	else
		echo "[✓] SSH SOCKS proxy already stopped."
	fi
}

create_tun() {
	if ! pgrep -qf "nohup tun2socks -device $INTERFACE_NAME"; then
		echo "[+] Starting tun2socks..."
		sudo nohup tun2socks \
			-device "$INTERFACE_NAME" \
			-proxy "socks5://127.0.0.1:$SOCKS_PORT" \
			-tun-post-up "ifconfig $INTERFACE_NAME $INTERFACE_IP $INTERFACE_IP up" 2>&1 |
			tee -a "$LOG_FILE" >/dev/null &
		sleep 1
	else
		echo "[✓] tun2socks already running."
	fi
}

destroy_tun() {
	if ifconfig "$INTERFACE_NAME" 2>/dev/null | grep -q "$INTERFACE_NAME"; then
		echo "[−] Shutting down TUN interface $INTERFACE_NAME..."
		sudo ifconfig "$INTERFACE_NAME" down
	else
		echo "[✓] TUN interface $INTERFACE_NAME already removed."
	fi

	if pgrep -qf "nohup tun2socks -device $INTERFACE_NAME"; then
		echo "[−] Killing tun2socks process..."
		pkill -f "nohup tun2socks -device $INTERFACE_NAME"
	else
		echo "[✓] tun2socks already stopped."
	fi
}

map_domains() {
	if [ ! -f "$DOMAINS" ] || [ ! -r "$DOMAINS" ]; then
		echo "Warning: '$DOMAINS' is either not a regular file or not readable. Nothing to map."
		return 0
	fi

	while IFS= read -r DOMAIN; do
		echo "[*] Resolving $DOMAIN via SSH host..."

		# shellcheck disable=SC2029
		IP=$(ssh -n "$SSH_HOST" getent hosts "$DOMAIN" | grep -Eo '(\d{1,3}\.){3}\d{1,3}' | head -n1)

		if [ -z "$IP" ]; then
			echo "[!] Could not resolve $DOMAIN via SSH — skipping"
			continue
		fi

		echo "[+] $DOMAIN resolves to $IP"

		if netstat -rn | grep -q "$IP/32"; then
			echo "[✓] Route for $IP already exists."
		else
			echo "[+] Adding route for $IP via $TUN_IP..."
			sudo route -n add -net "$IP/32" "$INTERFACE_IP"
		fi

		echo "[+] Updating /etc/hosts with $IP $DOMAIN..."
		sudo sed -i '' "/$DOMAIN/d" /etc/hosts
		printf "%s\t%s\n" "$IP" "$DOMAIN" | sudo tee -a /etc/hosts >/dev/null
	done <"$DOMAINS"
}

unmap_domains() {
	if [ ! -f "$DOMAINS" ] || [ ! -r "$DOMAINS" ]; then
		echo "Warning: '$DOMAINS' is either not a regular file or not readable. Nothing to unmap."
		return 0
	fi

	while IFS= read -r DOMAIN; do
		echo "[*] Looking for $DOMAIN in /etc/hosts..."

		IP=$(grep -v '^#' /etc/hosts | grep "$DOMAIN" | awk '{print $1}')

		if [ -z "$IP" ]; then
			echo "[!] Could not find $DOMAIN — skipping"
			continue
		fi

		echo "[−] Removing route for $IP..."
		sudo route -n delete -net "$IP/32" "$INTERFACE_IP"

		echo "[-] Removing $DOMAIN from /etc/hosts..."
		sudo sed -i '' "/$DOMAIN/d" /etc/hosts
	done <"$DOMAINS"
}

start() {
	sudo -v
	create_ssh_tunnel
	create_tun
	map_domains
}

stop() {
	sudo -v
	unmap_domains
	destroy_tun
	destroy_ssh_tunnel
}

main() {
	parse_args "$@"
	load_config

	case "$ACTION" in
	start)
		start
		;;
	stop)
		stop
		;;
	*)
		echo "Error: invalid action"
		echo "Try '$0 --help' for more information"
		exit 1
		;;
	esac
}

main "$@"
