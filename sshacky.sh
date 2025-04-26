#!/usr/bin/env bash

set -euo pipefail

CONFIG="$HOME/.config/sshacky/config.json"
DOMAINS=()
INTERFACE_IP="198.18.0.1"
INTERFACE_NAME="utun123"
PROFILE=""
SOCKS_PORT="1080"
SSH_HOST=""
SHOW_HELP=0
SHOW_VERSION=0
VERSION="0.3.0"
ACTION=""
LOG_FILE="/tmp/sshacky-$(date "+%Y%m%d").log"
KEEP_ALIVE_INTERVAL=30
KEEP_ALIVE_COUNT=3
OPTS=()
ARGS=()

show_usage() {
	cat <<EOF
Usage: sshacky [options...] <start|stop>

 --config               Configuration file (default: ~/.config/sshacky/config.cfg)
 --domains              Comma-separated list of domains (e.g., one.com,two.com)
 --help                 Show usage and exit
 --interface-ip         IP address for the TUN interface (default: 198.18.0.1)
 --interface-name       TUN interface name (default: utun123)
 --profile              Profile from the configuration file to load
 --socks-port           Port for the SSH tunnel (default: 1080)
 --ssh-host             User and host to create the SSH tunnel (e.g., user@jumpbox)
 --version              Show version and exit
EOF
}

show_version() {
	echo "sshacky v$VERSION"
}

parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--config)
			CONFIG="$2"
			shift 2
			;;
		--domains)
			OPTS+=("$1")
			shift

			if [[ -z "$1" || "$1" == --* ]]; then
				echo "Error: invalid domains" >&2
				echo "Try '$0 --help' for more information" >&2
				exit 1
			fi

			IFS=',' read -ra DOMAINS <<<"$1"
			shift
			;;
		--interface-ip)
			OPTS+=("$1")
			INTERFACE_IP="$2"
			shift 2
			;;
		--interface-name)
			OPTS+=("$1")
			INTERFACE_NAME="$2"
			shift 2
			;;
		--profile)
			PROFILE="$2"
			shift 2
			;;
		--socks-port)
			OPTS+=("$1")
			SOCKS_PORT="$2"
			shift 2
			;;
		--ssh-host)
			OPTS+=("$1")
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
			ARGS+=("$1")
			shift
			;;
		esac
	done

	if [[ "$SHOW_HELP" -eq 1 ]]; then
		show_usage
		exit 0
	fi

	if [[ "$SHOW_VERSION" -eq 1 ]]; then
		show_version
		exit 0
	fi

	if [[ "${#ARGS[@]}" -eq 0 ]]; then
		echo "Error: missing action argument" >&2
		echo "Try '$0 --help' for more information" >&2
		exit 1
	fi

	ACTION="${ARGS[0]}"

	case "$ACTION" in
	start | stop) ;;
	*)
		echo "Error: invalid action '$ACTION'" >&2
		echo "Try '$0 --help' for more information" >&2
		exit 1
		;;
	esac
}

contains() {
	local item="$1"
	shift

	for element in "$@"; do
		[[ "$element" == "$item" ]] && return 0
	done

	return 1
}

assign_if_unset() {
	local var="$1"
	local key
	key="$(echo "$var" | tr '[:upper:]' '[:lower:]')"
	local flag="--${key//_/-}"
	local current_value="${!var:-}"
	local json="$2"

	if ! contains "$flag" "${OPTS[@]-}"; then
		printf -v "$var" '%s' "$(jq -r --arg current "$current_value" ".${key} // \$current" <<<"$json")"
	fi
}

parse_config() {
	local json="$1"

	assign_if_unset INTERFACE_IP "$json"
	assign_if_unset INTERFACE_NAME "$json"
	assign_if_unset SOCKS_PORT "$json"
	assign_if_unset SSH_HOST "$json"

	if ! contains '--domains' "${OPTS[@]-}"; then
		DOMAINS=()
		while IFS= read -r DOMAIN; do
			DOMAINS+=("$DOMAIN")
		done < <(jq -r '.domains // [] | .[]' <<<"$json")
	fi
}

load_config() {
	if [[ ! -f "$CONFIG" || ! -r "$CONFIG" ]]; then
		return 0
	fi

	if ! jq empty "$CONFIG" >/dev/null 2>&1; then
		echo "Error: invalid configuration file '$CONFIG'" >&2
		exit 1
	fi

	parse_config "$(jq -cM '. | del(.profiles)' "$CONFIG")"

	if [[ -n "$PROFILE" ]]; then
		local profile
		profile=$(jq -cM ".profiles.$PROFILE // empty" "$CONFIG")

		if [[ -z "$profile" ]]; then
			echo "Error: profile '$PROFILE' not found in configuration file '$CONFIG'" >&2
			exit 1
		fi

		parse_config "$profile"
	fi
}

ssh_cmd() {
	echo "ssh -fNT -o ServerAliveInterval=$KEEP_ALIVE_INTERVAL -o ServerAliveCountMax=$KEEP_ALIVE_COUNT -D $SOCKS_PORT $SSH_HOST"
}

create_ssh_tunnel() {
	if [[ -z "$SSH_HOST" ]]; then
		echo "Error: missing SSH host" >&2
		echo "Try '$0 --help' for more information" >&2
		exit 1

	fi

	local cmd
	cmd="$(ssh_cmd)"

	if ! pgrep -qf "$cmd"; then
		echo "[+] Starting SSH SOCKS5 proxy..."
		if eval "$cmd"; then
			echo "[✓] SSH SOCKS5 proxy started."
			sleep 1
		else
			echo "[-] Failed to start SSH SOCKS5 proxy." >&2
			exit 1
		fi
	else
		echo "[✓] SSH SOCKS proxy already running."
	fi
}

destroy_ssh_tunnel() {
	local cmd
	cmd="$(ssh_cmd)"

	if pgrep -qf "$cmd"; then
		echo "[−] Killing SSH SOCKS tunnel on port $SOCKS_PORT..."
		pkill -f "$cmd"
	else
		echo "[✓] SSH SOCKS proxy already stopped."
	fi
}

tun2socks_cmd() {
	echo "nohup tun2socks -device $INTERFACE_NAME"
}

create_tun() {
	local cmd
	cmd="$(tun2socks_cmd)"

	if ! pgrep -qf "$cmd"; then
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
	if ifconfig "$INTERFACE_NAME" &>/dev/null; then
		echo "[−] Shutting down TUN interface $INTERFACE_NAME..."
		sudo ifconfig "$INTERFACE_NAME" down
	else
		echo "[✓] TUN interface $INTERFACE_NAME already removed."
	fi

	local cmd
	cmd="$(tun2socks_cmd)"

	if pgrep -qf "$cmd"; then
		echo "[−] Killing tun2socks process..."
		pkill -f "$cmd"
	else
		echo "[✓] tun2socks already stopped."
	fi
}

add_host() {
	local ip="$1"
	local domain="$2"

	sudo sed -i '' "/[[:space:]]$domain$/d" /etc/hosts
	printf "%s\t%s\n" "$ip" "$domain" | sudo tee -a /etc/hosts >/dev/null
}

map_domains() {
	if [[ "${#DOMAINS[@]}" -eq 0 ]]; then
		echo "Warning: domains is empty. Nothing to map."
		return 0
	fi

	for DOMAIN in "${DOMAINS[@]}"; do
		echo "[*] Resolving $DOMAIN via SSH host..."

		# shellcheck disable=SC2029
		IP=$(ssh -n "$SSH_HOST" getent hosts "$DOMAIN" | awk '{ print $1 }' | head -n1)

		if [[ -z "$IP" ]]; then
			echo "[!] Could not resolve $DOMAIN via SSH — skipping"
			continue
		fi

		echo "[+] $DOMAIN resolves to $IP"

		if netstat -rn | grep -q -F "$IP/32"; then
			echo "[✓] Route for $IP already exists."
		else
			echo "[+] Adding route for $IP via $INTERFACE_IP..."
			sudo route -n add -net "$IP/32" "$INTERFACE_IP"
		fi

		echo "[+] Updating /etc/hosts with $IP $DOMAIN..."
		add_host "$IP" "$DOMAIN"
	done
}

remove_host() {
	local domain="$1"

	sudo sed -i '' "/[[:space:]]$domain$/d" /etc/hosts
}

unmap_domains() {
	if [[ "${#DOMAINS[@]}" -eq 0 ]]; then
		echo "Warning: domains is empty. Nothing to unmap."
		return 0
	fi

	for DOMAIN in "${DOMAINS[@]}"; do
		echo "[*] Looking for $DOMAIN in /etc/hosts..."

		IP=$(grep -v '^#' /etc/hosts | grep -F "$DOMAIN" | awk '{print $1}')

		if [[ -z "$IP" ]]; then
			echo "[!] Could not find $DOMAIN — skipping"
			continue
		fi

		echo "[−] Removing route for $IP..."
		sudo route -n delete -net "$IP/32" "$INTERFACE_IP"

		echo "[-] Removing $DOMAIN from /etc/hosts..."
		remove_host "$DOMAIN"
	done
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
		echo "Error: invalid action" >&2
		echo "Try '$0 --help' for more information" >&2
		exit 1
		;;
	esac
}

main "$@" || {
	echo "Something went wrong. Exiting." >&2
	exit 1
}
