#!/usr/bin/env bash

set -euo pipefail

config="$HOME/.config/sshtun/config.json"
pid_dir="$HOME/.cache/sshtun"
domains=()
interface_ip="198.18.0.1"
profile=""
socks_port="1080"
ssh_host=""
edit_config=0
show_config=0
show_help=0
show_verbose=0
show_version=0
version="0.7.0"
action=""
log_file="/tmp/sshtun-$(date "+%Y%m%d").log"
keep_alive_interval=30
keep_alive_count=3
opts=()
args=()
os="$(uname)"

if [[ "$os" == Darwin ]]; then
	interface_name='utun123'
	sed_i=("sed" "-i" "")
	start_tun='create_tun_mac'
	stop_tun='destroy_tun_mac'
	add_route='add_route_mac'
	del_route='del_route_mac'
else
	interface_name='tun0'
	sed_i=("sed" "-i")
	start_tun='create_tun_linux'
	stop_tun='destroy_tun_linux'
	add_route='add_route_linux'
	del_route='del_route_linux'
fi

print_usage() {
	cat <<EOF
Usage: sshtun [options...] <start|stop|status>

 --config               Configuration file (default: ~/.config/sshtun/config.cfg)
 --domains              Comma-separated list of domains (e.g., one.com,two.com)
 --help                 Show usage and exit
 --interface-ip         IP address for the TUN interface (default: 198.18.0.1)
 --interface-name       TUN interface name (default: $interface_name)
 --profile              Profile from the configuration file to load
 --edit-config          Edit configuration file
 --show-config          Show configuration and exit
 --socks-port           Port for the SSH tunnel (default: 1080)
 --ssh-host             User and host to create the SSH tunnel (e.g., user@jumpbox)
 --verbose              Show detailed information about the running process
 --version              Show version and exit
EOF
}

print_version() {
	echo "sshtun v$version"
}

print_config() {
	if [[ -f "$config" ]]; then
		jq '.' "$config"
	fi
}

print_status() {
	if [[ ! -d "$pid_dir" ]]; then
		return 0
	fi

	local lines=()
	local colsize=12

	while read -r subdir; do
		local file="$subdir/pids"

		if [[ ! -s "$file" ]]; then
			continue
		fi

		local profile_name
		profile_name="$(basename "$subdir")"

		if [[ "${#profile_name}" -gt colsize ]]; then
			colsize=${#profile_name}
		fi

		local ssh_status="[…] unknown"
		local tun_status="[…] unknown"

		while IFS='=' read -r program_name pid; do
			local stat
			if is_running "$pid"; then
				stat="[✓] running"
			else
				stat="[✗] stopped"
			fi

			case "$program_name" in
			ssh)
				ssh_status="$stat"
				;;
			tun2socks)
				tun_status="$stat"
				;;
			*) ;;
			esac
		done <"$file"

		lines+=("$profile_name|$ssh_status|$tun_status")
	done < <(find "$pid_dir" -mindepth 1 -maxdepth 1 -type d)

	if [[ "${#lines[@]}" -gt 0 ]]; then
		printf "%-${colsize}s %-12s %-12s\n" "PROFILE" "SSH" "TUN"

		for line in "${lines[@]}"; do
			IFS='|' read -r profile_name ssh_status tun_status <<<"$line"
			printf "%-${colsize}s %-14s %-14s\n" "$profile_name" "$ssh_status" "$tun_status"
		done
	fi
}

open_config() {
	local preferred="${EDITOR:-${VISUAL:-}}"
	local fallbacks=(nvim vim vi nano)
	local editor

	if command -v "$preferred" >/dev/null 2>&1; then
		editor="$preferred"
	else
		for fallback in "${fallbacks[@]}"; do
			if command -v "$fallback" >/dev/null 2>&1; then
				editor="$fallback"
				break
			fi
		done
	fi

	if [[ -z "$editor" ]]; then
		echo "No suitable text editor found. Set the EDITOR or VISUAL environment variable with your preferred editor."
		return 1
	fi

	if [[ ! -f "$config" ]]; then
		echo "Configuration file $config not found."
		local answer
		read -r -p "Would you like to create it? [Y/n]: " answer

		case "$answer" in
		[yY])
			mkdir -p "$(dirname "$config")"
			printf "{\n}\n" >"$config"
			;;
		*)
			return 1
			;;
		esac
	fi

	"$editor" "$config"
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
		--edit-config)
			edit_config=1
			shift
			;;
		--show-config)
			show_config=1
			shift
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
		--verbose)
			show_verbose=1
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

	if [[ "$edit_config" -eq 1 ]]; then
		open_config && exit 0 || exit 1
	fi

	if [[ "$show_config" -eq 1 ]]; then
		print_config && exit 0 || exit 1
	fi

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
	start | stop | status) ;;
	*)
		echo "Error: invalid action '$action'" >&2
		echo "Try '$0 --help' for more information" >&2
		exit 1
		;;
	esac
}

log() {
	if [[ "$show_verbose" -eq 1 ]]; then
		echo "$1"
	fi
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
		while IFS= read -r domain; do
			domains+=("$domain")
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

save_pid() {
	local pid
	local key="$1"
	local cmd="$2"
	local dir="$pid_dir/${profile:-default}"
	local file="$dir/pids"

	pid=$(pgrep -f "$cmd" | head -n1)
	mkdir -p "$dir"
	touch "$file"
	"${sed_i[@]}" "/^${key}=/d" "$file"
	echo "$key=$pid" >>"$file"
}

delete_pids() {
	local file="$pid_dir/${profile:-default}/pids"

	if [[ -f "$file" ]]; then
		rm "$file"
	fi
}

get_pid() {
	local key="$1"
	local file="$pid_dir/${profile:-default}/pids"

	if [[ -f "$file" ]]; then
		awk -F= -v k="$key" '$1 == k { print $2 }' "$file"
	fi
}

is_running() {
	local pid="$1"

	if [[ -z "$pid" || ! "$pid" =~ ^[0-9]+$ ]]; then
		return 1
	fi

	sudo kill -0 "$pid" 2>/dev/null
}

create_ssh_tunnel() {
	if [[ -z "$ssh_host" ]]; then
		echo "Error: missing SSH host" >&2
		echo "Try '$0 --help' for more information" >&2
		exit 1

	fi

	local program_name="ssh"
	local pid
	pid=$(get_pid "$program_name")

	if is_running "$pid"; then
		log "[✓] SSH SOCKS tunnel already running."
	else
		log "[…] Starting SSH SOCKS tunnel on port $socks_port"
		ssh -fNT \
			-o ServerAliveInterval="$keep_alive_interval" \
			-o ServerAliveCountMax="$keep_alive_count" \
			-D "$socks_port" \
			"$ssh_host"
		sleep 1

		local cmd="ssh -fNT .* -D $socks_port $ssh_host"
		save_pid "$program_name" "$cmd"
	fi
}

destroy_ssh_tunnel() {
	local program_name="ssh"
	local pid
	pid=$(get_pid "$program_name")

	if is_running "$pid"; then
		log "[…] Killing SSH SOCKS tunnel on port $socks_port"
		kill "$pid"
	else
		log "[✓] SSH SOCKS tunnel already stopped."
	fi
}

create_tun_mac() {
	sudo nohup tun2socks \
		-device "$interface_name" \
		-proxy "socks5://127.0.0.1:$socks_port" \
		-tun-post-up "ifconfig $interface_name $interface_ip $interface_ip up" 2>&1 |
		tee -a "$log_file" >/dev/null &
}

create_tun_interface_linux() {
	sudo ip tuntap add mode tun dev "$interface_name"
	sudo ip addr add "$interface_ip" dev "$interface_name"
	sudo ip link set dev "$interface_name" up
}

create_tun_linux() {
	create_tun_interface_linux
	sudo nohup tun2socks \
		-device "$interface_name" \
		-proxy "socks5://127.0.0.1:$socks_port" |
		tee -a "$log_file" >/dev/null &
}

create_tun() {
	local program_name="tun2socks"
	local pid
	pid=$(get_pid "tun2socks")

	if is_running "$pid"; then
		log "[✓] tun2socks already running."
	else
		log "[…] Starting tun2socks"
		"$start_tun"
		sleep 1

		local cmd="nohup tun2socks -device $interface_name"
		save_pid "$program_name" "$cmd"
	fi
}

destroy_tun_mac() {
	local pid="$1"
	sudo kill "$pid"
}

destroy_tun_linux() {
	local pid="$1"
	sudo kill "$pid"

	if ip link show "$interface_name" &>/dev/null; then
		log "[…] Deleting TUN interface $interface_name"
		sudo ip tuntap del mode tun dev "$interface_name"
	else
		log "[✓] TUN interface $interface_name already removed."
	fi
}

destroy_tun() {
	local program_name="tun2socks"
	local pid
	pid=$(get_pid "$program_name")

	if is_running "$pid"; then
		log "[…] Killing tun2socks process"
		"$stop_tun" "$pid"
	else
		log "[✓] tun2socks already stopped."
	fi
}

remove_host() {
	local domain="$1"
	sudo "${sed_i[@]}" "/[[:space:]]$domain$/d" /etc/hosts
}

add_host() {
	local ip="$1"
	local domain="$2"
	remove_host "$domain"
	printf "%s\t%s\n" "$ip" "$domain" | sudo tee -a /etc/hosts >/dev/null
}

add_route_mac() {
	local ip="$1"

	if netstat -rn | grep -q -F "$ip/32"; then
		log "[✓] Route for $ip already exists."
	else
		log "[…] Adding route for $ip via $interface_ip"
		sudo route -n add -net "$ip" "$interface_ip" >/dev/null
	fi
}

add_route_linux() {
	local ip="$1"

	if ip route show | grep -q -F "'$ip '"; then
		log "[✓] Route for $ip already exists."
	else
		log "[…] Adding route for $ip via $interface_ip"
		sudo ip route add "$ip" via "$interface_ip" dev "$interface_name"
	fi
}

map_domains() {
	if [[ "${#domains[@]}" -eq 0 ]]; then
		log "[!] Domains is empty. Nothing to map."
		return 0
	fi

	log "[…] Resolving domains via SSH host"
	local dns_table
	dns_table=$(printf "%s\n" "${domains[@]}" | ssh "$ssh_host" 'xargs -I{} sh -c '"'"'getent hosts {} | awk "{print \$1 \"\t\" \"{}\"}"'"'"'')
	local resolved_names=""

	while IFS= read -r line; do
		local ip=${line%%$'\t'*}
		local domain=${line#*$'\t'}

		resolved_names+="$domain"$'\n'
		"$add_route" "$ip"

		log "[…] Updating /etc/hosts with $ip $domain"
		add_host "$ip" "$domain"
	done <<<"$dns_table"

	for domain in "${domains[@]}"; do
		if ! grep -qxF "$domain" <<<"${resolved_names[@]}"; then
			log "[✗] Could not resolve $domain via SSH"
		fi
	done
}

del_route_mac() {
	local ip="$1"
	sudo route -n delete -net "$ip" "$interface_ip" >/dev/null
}

del_route_linux() {
	local ip="$1"
	sudo ip route del "$ip" via "$interface_ip" dev "$interface_name"
}

unmap_domains() {
	if [[ "${#domains[@]}" -eq 0 ]]; then
		log "[!] Domains is empty. Nothing to unmap."
		return 0
	fi

	for domain in "${domains[@]}"; do
		log "[…] Looking for $domain in /etc/hosts"

		local ip
		ip=$(grep -v '^#' /etc/hosts | grep -F "$domain" | awk '{print $1}')

		if [[ -z "$ip" ]]; then
			log "[!] Could not find $domain"
			continue
		fi

		log "[…] Removing route for $ip"
		"$del_route" "$ip"

		log "[…] Removing $domain from /etc/hosts"
		remove_host "$domain"
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
	delete_pids
}

status() {
	sudo -v
	print_status
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
	status)
		status
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
