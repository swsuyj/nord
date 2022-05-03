#!/bin/bash

set -eu

# Prerequisites
if [[ ! -f ./nord-firewall ]]
then
	echo "Please compile nord-firewall.cpp"
	exit 1
fi

NORD_DATA_DIR="${XDG_DATA_HOME:-/usr/local/share}/nord"
NORD_CONFIG_DIR="${XDG_CONFIG_HOME:-/etc}/nord"
NORD_CACHE_DIR="${XDG_CACHE_HOME:-/var/cache}/nord"
NORD_SYSTEMD_DIR="/etc/systemd/system"
NORD_BIN_DIR="/usr/local/bin"
NORD_USER_INSTALL=false

function set_user() {
	NORD_DATA_DIR="${XDG_DATA_DIR:-$HOME/.local/share}/nord"
	NORD_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/nord"
	NORD_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/nord"
	NORD_SYSTEMD_DIR="$HOME/.local/share/systemd/system"
	NORD_BIN_DIR="$HOME/.local/bin"
	NORD_USER_INSTALL=true
}

if [[ "$(id -u)" -ne 0 ]]
then
	echo "Installing for current user. Use sudo if you want system install."
	set_user
fi

while [[ $# -gt 0 ]]
do
	case $1 in
		-u|--user)
			set_user
			shift
			;;
	esac
done

echo "Ensuring directories exists"
for d in "$NORD_DATA_DIR" "$NORD_CONFIG_DIR" "$NORD_CACHE_DIR" "$NORD_SYSTEMD_DIR" "$NORD_BIN_DIR" "$(manpath)" "$NORD_DATA_DIR/ovpn"
do
	d=${d//:*}
	#echo "Creating directory $d"
	mkdir -p "$d"
done

echo "Copying files"
cp nord-firewall "$NORD_BIN_DIR"
cp nord "$NORD_BIN_DIR"

conf="$NORD_CONFIG_DIR"/nord.conf
[[ ! -f "$conf" ]] && cp nord.conf.default "$conf"


service="$NORD_SYSTEMD_DIR"/nord.service
[[ ! -f "$service" ]] && cp nord.service "$service"
timer="$NORD_SYSTEMD_DIR"/nord.timer
[[ ! -f "$timer" ]] && cp nord.timer "$timer"

# Install man page
cp doc/nord.1 "$(manpath | sed 's/:.*//')"/man1/
mandb $([[ $NORD_USER_INSTALL == true ]] && echo --user-db) >/dev/null
