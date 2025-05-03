#!/usr/bin/env bash

set -euo pipefail

config="$HOME/.config/sshacky/config.json"
domains=()
interface_ip="198.18.0.1"
interface_name="utun123"
profile=""
socks_port="1080"
ssh_host=""
show_help=0
show_version=0
version="0.3.0"
action=""
log_file="/tmp/sshacky-$(date "+%Y%m%d").log"
keep_alive_interval=30
keep_alive_count=3
opts=()
args=()

print_usage() {
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

print_version() {
	echo "sshacky v$version"
}

parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--config)
			config="$2"
			shift 2
			;;
		--domains)
			opts+=("$1")
			shift

			if [[ -z "$1" || "$1" == --* ]]; then
				echo "Error: invalid domains" >&2
				echo "Try '$0 --help' for more information" >&2
				exit 1
			fi

			IFS=',' read -ra domains <<<"$1"
			shift
			;;
		--interface-ip)
			opts+=("$1")
			interface_ip="$2"
			shift 2
			;;
		--interface-name)
			opts+=("$1")
			interface_name="$2"
			shift 2
			;;
		--profile)
			profile="$2"
			shift 2
			;;
		--socks-port)
			opts+=("$1")
			socks_port="$2"
			shift 2
			;;
		--ssh-host)
			opts+=("$1")
			ssh_host="$2"
			shift 2
			;;
		--help)
			show_help=1
			shift
			;;
		--version)
			show_version=1
			shift
			;;
		-*)
			echo "Unknown option: $1"
			echo "Try '$0 --help' for more information"
			exit 1
			;;
		*)
			args+=("$1")
			shift
			;;
		esac
	done

	if [[ "$show_help" -eq 1 ]]; then
		print_usage
		exit 0
	fi

	if [[ "$show_version" -eq 1 ]]; then
		print_version
		exit 0
	fi

	if [[ "${#args[@]}" -eq 0 ]]; then
		echo "Error: missing action argument" >&2
		echo "Try '$0 --help' for more information" >&2
		exit 1
	fi

	action="${args[0]}"

	case "$action" in
	start | stop) ;;
	*)
		echo "Error: invalid action '$action'" >&2
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

	if ! contains "$flag" "${opts[@]:-}"; then
		printf -v "$var" '%s' "$(jq -r --arg current "$current_value" ".${key} // \$current" <<<"$json")"
	fi
}

parse_config() {
	local json="$1"

	assign_if_unset interface_ip "$json"
	assign_if_unset interface_name "$json"
	assign_if_unset socks_port "$json"
	assign_if_unset ssh_host "$json"

	if ! contains '--domains' "${opts[@]:-}"; then
		domains=()
		while IFS= read -r DOMAIN; do
			domains+=("$DOMAIN")
		done < <(jq -r '.domains // [] | .[]' <<<"$json")
	fi
}

load_config() {
	if [[ ! -f "$config" || ! -r "$config" ]]; then
		return 0
	fi

	if ! jq empty "$config" >/dev/null 2>&1; then
		echo "Error: invalid configuration file '$config'" >&2
		exit 1
	fi

	parse_config "$(jq -cM '. | del(.profiles)' "$config")"

	if [[ -n "$profile" ]]; then
		local profile_config
		profile_config=$(jq -cM ".profiles.$profile // empty" "$config")

		if [[ -z "$profile_config" ]]; then
			echo "Error: profile '$profile' not found in configuration file '$config'" >&2
			exit 1
		fi

		parse_config "$profile_config"
	fi
}

ssh_cmd() {
	echo "ssh -fNT -o ServerAliveInterval=$keep_alive_interval -o ServerAliveCountMax=$keep_alive_count -D $socks_port $ssh_host"
}

create_ssh_tunnel() {
	if [[ -z "$ssh_host" ]]; then
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
		echo "[−] Killing SSH SOCKS tunnel on port $socks_port..."
		pkill -f "$cmd"
	else
		echo "[✓] SSH SOCKS proxy already stopped."
	fi
}

tun2socks_cmd() {
	echo "nohup tun2socks -device $interface_name"
}

create_tun() {
	local cmd
	cmd="$(tun2socks_cmd)"

	if ! pgrep -qf "$cmd"; then
		echo "[+] Starting tun2socks..."
		sudo nohup tun2socks \
			-device "$interface_name" \
			-proxy "socks5://127.0.0.1:$socks_port" \
			-tun-post-up "ifconfig $interface_name $interface_ip $interface_ip up" 2>&1 |
			tee -a "$log_file" >/dev/null &
		sleep 1
	else
		echo "[✓] tun2socks already running."
	fi
}

destroy_tun() {
	if ifconfig "$interface_name" &>/dev/null; then
		echo "[−] Shutting down TUN interface $interface_name..."
		sudo ifconfig "$interface_name" down
	else
		echo "[✓] TUN interface $interface_name already removed."
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
	if [[ "${#domains[@]}" -eq 0 ]]; then
		echo "Warning: domains is empty. Nothing to map."
		return 0
	fi

	for DOMAIN in "${domains[@]}"; do
		echo "[*] Resolving $DOMAIN via SSH host..."

		# shellcheck disable=SC2029
		IP=$(ssh -n "$ssh_host" getent hosts "$DOMAIN" | awk '{ print $1 }' | head -n1)

		if [[ -z "$IP" ]]; then
			echo "[!] Could not resolve $DOMAIN via SSH — skipping"
			continue
		fi

		echo "[+] $DOMAIN resolves to $IP"

		if netstat -rn | grep -q -F "$IP/32"; then
			echo "[✓] Route for $IP already exists."
		else
			echo "[+] Adding route for $IP via $interface_ip..."
			sudo route -n add -net "$IP/32" "$interface_ip"
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
	if [[ "${#domains[@]}" -eq 0 ]]; then
		echo "Warning: domains is empty. Nothing to unmap."
		return 0
	fi

	for DOMAIN in "${domains[@]}"; do
		echo "[*] Looking for $DOMAIN in /etc/hosts..."

		IP=$(grep -v '^#' /etc/hosts | grep -F "$DOMAIN" | awk '{print $1}')

		if [[ -z "$IP" ]]; then
			echo "[!] Could not find $DOMAIN — skipping"
			continue
		fi

		echo "[−] Removing route for $IP..."
		sudo route -n delete -net "$IP/32" "$interface_ip"

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

	case "$action" in
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
