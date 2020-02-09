#!/bin/bash

wget="/usr/bin/wget"
curl="/usr/bin/curl"
sed="/usr/bin/sed"
ip="/usr/bin/ip"
fwd="/usr/bin/firewall-cmd"
unzip="/usr/bin/unzip"
nmcli="/usr/bin/nmcli"

PROGNAME="nord"
CONF_DIR="$HOME/.config/nord"
[[ -n $XDF_CONFIG_HOME ]] && CONF_DIR="$XDF_CONFIG_HOME/nord"
DATA_DIR="$HOME/.local/share/nord"
[[ -n $XDF_DATA_HOME ]] && CONF_DIR="$XDF_DATA_HOME/nord"
CACHE_DIR="$HOME/.cache/nord"
[[ -n $XDF_CACHE_HOME ]] && CONF_DIR="$XDF_CACHE_HOME/nord"
OVPN_DIR="$DATA_DIR/ovpn"
CONN_TYPE="tcp"
CONF_FILE="$CONF_DIR/nord.conf"
CONN_NAME="current_connection"
AUTH_FILE="$CONF_DIR/auth"
VPN_FILES="$CACHE_DIR/nordvpnfiles.zip"
TOP_SERVERS_FILE="$CONF_DIR/topservers.conf"
VPN_FILE_URL="https://downloads.nordcdn.com/configs/archives/servers/ovpn.zip"
VPN_STATS_URL="https://nordvpn.com/api/server/stats"
CONN_DEST=""
# TODO use only country code
CONN_DEST_DEFAULT="nl690"
CONN_DEST_COUNTRY=""
nowhere="nowhere"
CONN_PORT=-1
CONN_TIMEOUT=5

NUM_SERVERS=4
PING_INTERVAL=1
PING_NUM=1

VERBOSE=1
VVERBOSE=1

KILL_SWITCH=0
CONF_LOADED=0

typeset -A config

typeset -A nosave
nosave=()
retvar=""
top_servers=()


typeset -A config
config=(
	["CONN_TYPE"]=$CONN_TYPE
	["CONN_PORT"]=$CONN_PORT
	["PING_NUM"]=$PING_NUM
	["PING_INTERVAL"]=$PING_INTERVAL
	["NUM_SERVERS"]=$NUM_SERVERS
	["CONN_TIMEOUT"]=$CONN_TIMEOUT
)



# Basic logging/output
function log () {
	echo -ne "$1"
}

# Error logging
function elog () {
	>&2 echo -ne "$1"
}

# Verbose logging
function vlog () {
	if [[ ${config["VERBOSE"]} -eq 1 ]]
	then
		echo -ne "$1"
	fi
}

# Very verbose logging
function vvlog () {
	if [[ ${config["VVERBOSE"]} -eq 1 || ${config["VERBOSE"]} -eq 1 ]]
	then
		echo -ne "$1"
	fi
}


# Usage:  toLower x
# Before: x is a non-empty string.
# After:  Returns x in lowercase.
function toLower () {
	echo $1 | tr '[:upper:]' '[:lower:]'
}


# Usage:  toUpper x
# Before: x is a non-empty string.
# After:  Returns x in uppercase.
function toUpper () {
	echo $1 | tr '[:lower:]' '[:upper:]'
}


# Usage:  getConfig
# Before: Config file contains config.
# After:  Config options on file have been printed to stout.
function getConfig () {
	while read line
	do
		if echo "$line" | grep -E "^[[:alpha:]_]+=\S+$" &>/dev/null
		then
			echo "$line"
		fi
	done < $CONF_FILE
}

# Usage:  loadConfig
# Before: Nothing.
# After:  User configurations have been loaded from user configuration file.
function loadConfig () {
	# See https://unix.stackexchange.com/a/206216

	vlog "Loading configurations... "

	# Create temp config, preventing starting logging output upon
	#  encountering the logging flag
	typeset -A temp_config

	if [[ -f $CONF_FILE ]]
	then
		vvlog "\n"
		while read line
		do
			if echo "$line" | grep -F = &>/dev/null
			then
				varname=$(echo "$line" | cut -d '=' -f 1)
				temp_config[$varname]=$(echo "$line" | cut -d '=' -f 2-)
				vvlog "Loading $varname as ${temp_config[$varname]}.\n"
			fi
		done < $CONF_FILE

		# Set connection port after loading.
		[[ ${temp_config[conn_type]} == "tcp" ]] && temp_config[conn_port]=443
		[[ ${temp_config[conn_type]} == "udp" ]] && temp_config[conn_port]=1194

		vlog "Done\n"
		temp_config["CONF_LOADED"]=1
	else
		vlog "Failed\n"
		return 1
	fi

	# Copy temp to permanent config
	config=()
	for key in "${!temp_config[@]}"
	do
		config["$key"]="${temp_config[$key]}"
	done

	# Load configs the nosaved config
	vvlog "Updating config with nosave.\n"
	for nokey in ${!nosave[@]}
	do
		vvlog "Changing $nokey from ${config[$nokey]} in config to ${nosave[$nokey]}.\n"
		config["$nokey"]=nosave["$nokey"]
	done
}


# Usage:  updateConfig k v x
# Before: k is the config item to be changed, the key
#          v is the new value of the item. x is optional.
# After:  k has been set to v in the config file,
#          and (if x is not "nosave") in the config variable.
function updateConfig () {
	if [[ -z $1 || -z $2 ]]
	then
		elog "Improper call to updateConfig. Aborting!\n"
		return 1
	fi

	vvlog "Updating $1 to $2 "

	if [[ $3 == "nosave" ]]
	then
		vvlog "non-save"
		nosave["$1"]=$2
		return 0
	fi
	vvlog "\n"

	vlog "Updating config file... "

	# Branching depending whether the config is present or not.
	if [[ -z $(grep $1 $CONF_FILE) ]]
	then
		vvlog "Failed.\nNew config options are not allowed.\n"
		elog "Invalig config '`toLower $1`'.\n"
		return 0
		sed -ci "$ a $1=$2" $CONF_FILE
	else
		sed -ci "s/^$1=.*/$1=$2/" $CONF_FILE
	fi
	vlog "Done\n"
	loadConfig
}


# Usage:  checkSetup
# Before: Nothing.
# After:  Returns 0 if all is set up.
#          Exits with code 1 otherwise.
function checkSetup () {
	vlog "Checking for required files and folders... "
	if [[
			! -d $CONF_DIR ||
			! -f $CONF_FILE ||
			! -d $DATA_DIR ||
			! -d $OVPN_DIR ||
			-z $(ls $OVPN_DIR)
		]]
	then
		elog "$PROGNAME seems to not be set up.\n"
		elog "Please run \`$PROGNAME setup\`\n"
		exit 1
	fi
	vlog "Done\n"
	return 0
}


# Usage:  loadTopServers
# Before: $top_servers has been initialized
# After:  $retvar has been filled with latest update on good servers,
#          unless stat server is unreachable, then $retvar is
#          filled with top servers saved on file. If the file is empty
#          or unreachable, a default location is used, specified by config.
function loadTopServers () {
	[[ ${config["CONF_LOADED"]} -ne 1 ]] && loadConfig

	vlog "Loading best servers from file... "

	noserv=0 # Flag indicating if there are any servers loaded
	if [[ -f $TOP_SERVERS_FILE ]]
	then
		top_servers=()
		while read line
		do
			if echo "$line" | grep -E "^[[:alpha:]]+[[:digit:]]+$" &>/dev/null
			then
				top_servers+=("$line")
			fi
		done < $TOP_SERVERS_FILE
		vlog "Done\n"

		# Check that top_servers is not empty
		if [[ ${#top_servers[@]} == 0 ]];then
			noserv=1
		fi
	else
		vlog "Failed\n"
		noserv=1
	fi

	if [[ $noserv == 1 ]]
	then
		top_servers=()
		top_servers+=("${config["CONN_DEST_DEFAULT"]}")
	fi

	vvlog "Top servers:\n"
	for x in ${top_servers[@]}; do
		vvlog "$x \t "
	done
	vvlog "\n"

	top_server=$(echo ${top_servers[@]} | sed 's/ /\n/g' | shuf | head -n 1)

	retvar=$top_server
	return 0
}



# Usage:  getHostIP x
# Before: .ovpn files are available. x is of the form [a-z]{2}\d+
# After:  ipv4 address of x
function getHostIP () {
	[[ ${config["CONF_LOADED"]} -ne 1 ]] && loadConfig
	dest_ip=$( \
		grep "^remote " \
		$OVPN_DIR/ovpn_${config["CONN_TYPE"]}/$1.nordvpn.com.tcp.ovpn \
		| $sed 's/remote \(\(\w\+\.\?\)\+\) \w\+$/\1/' \
	)
	retvar="$dest_ip"
}

# Usage:  firewallPunch x
# Before: firewalld is in use and running. x is of the form [a-z]{2}\d+ 
# After:  firewalld contains an exception to allow traffic to x over tun0
function firewallPunch () {
	[[ ${config["CONF_LOADED"]} -ne 1 ]] && loadConfig
	vlog "Punching hole in firewall for $1... "
	if [[ ${config["KILL_SWITCH"]} -eq 0 || $1 == $nowhere ]]
	then
		vlog "Kill switch is off. Aborting!\n"
		return 0
	fi

	getHostIP $1
	dest_ip=$retvar
	sudo $fwd \
		--quiet \
		--direct \
		--add-rule ipv4 \
		filter OUTPUT 10 \
		-p tcp \
		-m tcp \
		--dport ${config["CONN_PORT"]} \
		-d "$dest_ip" \
		-j ACCEPT
	vlog "Done\n"
}

# Usage:  firewallUnpunch x
# Before: firewalld is in use and running. x is of the form [a-z]{2}\d+
#         firewalldere is a hole in the firewall for x.
# After:  firewalld has no hole from firewallPunch for x
function firewallUnpunch () {
	[[ ${config["CONF_LOADED"]} -ne 1 ]] && loadConfig
	if [[ ${config["KILL_SWITCH"]} -eq 0 || $1 == $nowhere ]]
	then
		return 0
	fi
	vlog "Mending hole in firewall for $1... "
	getHostIP $1
	dest_ip=$retvar
	sudo $fwd \
		--quiet \
		--direct \
		--remove-rule ipv4 \
		filter OUTPUT 10 \
		-p tcp \
		-m tcp \
		--dport ${config["CONN_PORT"]} \
		-d "$dest_ip" \
		-j ACCEPT
	vlog "Done\n"
}


# Usage:  getRecommendedServer
# Before: Internet access is available.
# After:  If server fetching is successful, results of top-N
#          servers is saved in topservers.conf
#          Returns a random, single best server.
function getRecommendedServer () {
	[[ ${config["CONF_LOADED"]} -ne 1 ]] && checkSetup && loadConfig
	# Fetch servers with lowest load
	vlog "Fetching information on the load of NordVPN servers.\n"

	vlog "Getting nord stats... "

	vvlog "Is there an active connection? {$(nmcli connection show --active)}\n"
	stats=""
	[[ -n $(nmcli connection show --active) ]] &&
		[[ \
			${config["KILL_SWITCH"]} -eq 1 && \
			-n $(nmcli connection show --active | grep nordvpn) || \
			${config["KILL_SWITCH"]} -eq 0 \
		]] && \
		vvlog "Fetching stats now.\n" && \
		stats=$( \
			$curl \
				--connect-timeout ${config["CONN_TIMEOUT"]} \
				$VPN_STATS_URL \
		)

	# if no internet, load best servers.
	if [[ -z $stats ]]
	then
		if [[ ${config["KILL_SWITCH"]} -eq 0 ]]
		then
			log "No internet access.\n"
			exit 1
		fi
		vlog "Kill switch is on.\n"

		loadTopServers

		# Return random latest-best server
		retvar=$(echo ${retvar[@]} | sed 's/ /\n/g' | shuf | head -n 1)
		return 0
	else
		vlog "Done\n"
	fi

	# Filter collected statistics to reveal top N servers in terms of least load.
	if [[ ${config["OBFUSCATED"]} -eq 1 ]]
	then
		elog "Obfuscated server select has not been implemented yet.\n"
	fi
	selected_servers=$( \
		echo $stats \
		| $sed 's/^{\|}$//g' | $sed 's/,/\n/g' \
		| $sed 's/^"\(\w\{2\}\)\([^.]\+\)\.nordvpn\.com":{"percent":\(\w\+\)}$/\3 \1\2/' \
		| grep "$(ls -l $OVPN_DIR/ovpn_$CONN_TYPE \
		| grep "[a-z0-9]\+.nordvpn" \
		| $sed 's/.*\([a-z]\{2\}[0-9]\+\)\.nordvpn\.com.*/\1/')" \
		| sort -n \
		| cut -d ' ' -f 2 \
		| head -n `expr 5 \* ${config["NUM_SERVERS"]}` \
		| shuf \
		| head -n $NUM_SERVERS \
	)

	# Initialize server list, and ping times
	servers=()
	ping_times=()
	for server in $selected_servers; do
		servers+=($server)
		ping_times+=(-1)
	done

	vlog "Starting pinging of top servers.\n"
	# Ping top n servers to find the nearest
	#  (assuming ping time correlates with distance)
	for ((i=0; i<${#servers[@]}; i++)); do
		# TODO parallelize this loop

		times=$( \
			ping ${servers[$i]}.nordvpn.com -c ${config["PING_NUM"]} -i $PING_INTERVAL -q \
			| grep "rtt min/avg/max/mdev" \
		)

		if [[ -z $times ]]; then
			elog "Unable to ping NordVPN server ${servers[$i]}. Aborting!\n" 
			return 1
		fi

		ping_times[$i]=$( \
			echo $times | \
			$sed 's/^.*min\/avg\/max\/mdev = [0-9.]\+\/\([0-9]\+\).*$/\1/' \
		)
	done

	# Ensure all threads have completed
	vlog "Servers with lowest load have been pinged.\n"

	vlog "Saving top servers... "
	echo "" > $TOP_SERVERS_FILE # Clear saved server list.
	for ((i=0; i<${#servers[@]}; i++)); do
		vvlog "Server ${servers[$i]} has ping time ${ping_times[$i]}.\n"
		sed -ci "$ a ${servers[$i]}" $TOP_SERVERS_FILE
	done
	vlog "Done\n"

	# Fold over ping times to find the fastest server
	min_index=0
	min_ping=-1
	for ((i=0; i<${#servers[@]}; i++)); do
		vvlog "Ping time of $i: ${ping_times[$i]}\n"
		if [[ $min_ping == -1 || ${ping_times[$i]} -lt $min_ping ]]; then
			vvlog "Setting min_ping time to ${ping_times[$i]}.\n"
			min_ping=${ping_times[$i]}
			min_index=$i
		fi
	done
	vvlog "Server ${servers[$min_index]} has low load and "
	vvlog "ping time ${ping_times[$min_index]}, "
	vvlog "but lowest ping time is $min_ping.\n"

	retvar=${servers[$min_index]}
}




function killswitch () {
	[[ ${config["CONF_LOADED"]} -ne 1 ]] && loadConfig
	vlog "Turning the kill switch on/off requires root access.\n"
	vlog "You may be prompted for a password.\n"
	vlog "Turning kill switch $1...\n"
	if [[ $1 == "on" ]]
	then
		# Block all connections
		vvlog "Blocking all incoming and outgoing.\n"
		# Block all ipv6
		sudo $fwd -q --permanent --direct --add-rule ipv6 filter INPUT 0 -j DROP
		sudo $fwd -q --permanent --direct --add-rule ipv6 filter OUTPUT 0 -j DROP
		# Accept outgoing VPN
		sudo $fwd -q --permanent --direct --add-rule ipv4 filter OUTPUT 0 -o tun+ -j ACCEPT
		# Accept forwards
		sudo $fwd -q --permanent --direct --add-rule ipv4 filter INPUT 0 -i lo -j ACCEPT
		sudo $fwd -q --permanent --direct --add-rule ipv4 filter OUTPUT 0 -o lo -j ACCEPT
		sudo $fwd -q --permanent --direct --add-rule ipv4 filter FORWARD 0 -o tun+ -j ACCEPT
		sudo $fwd -q --permanent --direct --add-rule ipv4 filter FORWARD 0 -i tun+ -j ACCEPT
		# Default block in/out
		sudo $fwd -q --permanent --direct --add-rule ipv4 filter INPUT 999 -j DROP
		sudo $fwd -q --permanent --direct --add-rule ipv4 filter OUTPUT 999 -j DROP
		sudo $fwd -q --reload
		# Also punch a hole after the reload.
		updateConfig "KILL_SWITCH" 1
		vvlog "After updating config, punch a hole.\n"
		firewallPunch "${config["CONN_DEST"]}"

	elif [[ $1 == "off" ]]
	then
		## The reverse of the above.
		# Block all connections
		vvlog "Allowing incoming and outgoing.\n"
		# Block all ipv6
		sudo $fwd -q --permanent --direct --remove-rule ipv6 filter INPUT 0 -j DROP
		sudo $fwd -q --permanent --direct --remove-rule ipv6 filter OUTPUT 0 -j DROP
		# Accept outgoing VPN
		sudo $fwd -q --permanent --direct --remove-rule ipv4 filter OUTPUT 0 -o tun+ -j ACCEPT
		# Accept forwards
		sudo $fwd -q --permanent --direct --remove-rule ipv4 filter INPUT 0 -i lo -j ACCEPT
		sudo $fwd -q --permanent --direct --remove-rule ipv4 filter OUTPUT 0 -o lo -j ACCEPT
		sudo $fwd -q --permanent --direct --remove-rule ipv4 filter FORWARD 0 -o tun+ -j ACCEPT
		sudo $fwd -q --permanent --direct --remove-rule ipv4 filter FORWARD 0 -i tun+ -j ACCEPT
		# Default block in/out
		sudo $fwd -q --permanent --direct --remove-rule ipv4 filter INPUT 999 -j DROP
		sudo $fwd -q --permanent --direct --remove-rule ipv4 filter OUTPUT 999 -j DROP
		sudo $fwd -q --reload

		updateConfig "KILL_SWITCH" 0
	else
		vlog "Failed\n"
		elog "Invalid parameter to kill switch. Aborting!\n"
		return 1
	fi

	log "Successfully turned kill switch $1.\n"

	return 0
}


# Usage:  getLogin
# Before: Nothing.
# After:  Username and password is stored in plain text.
function getLogin () {
	echo "Please log in."
	echo -n "Username: "
	read username
	echo -n "Password: "
	read -s password
	echo ""
	vvlog "Creating auth file... "
	install -m 600 /dev/null $AUTH_FILE
	echo >> $AUTH_FILE
	vvlog "Done\n"
	sed -ci "1s/^/vpn.secrets.password:$password/" $AUTH_FILE
	
	updateConfig "USERNAME" $username
}


# Usage:  disconnect
# Before: A connection is up to Nord
# After:  The connection has been terminated.
function disconnect () {
	[[ ${config["CONF_LOADED"]} -ne 1 ]] && loadConfig
	output=$(nmcli connection show --active | grep nordvpn)
	vvlog "nmcli search results:\n{$output}\n"
	if [[ -z $output || ${config["CONN_DEST"]} == $nowhere ]]
	then
		vlog "No connection active. Aborting!\n"
		log "No active connection.\n"
		return 1
	fi
	dest="${config["CONN_DEST"]}.nordvpn.com.$CONN_TYPE"
	output=$($nmcli connection delete $dest)
	vlog "${output[@]}\n"
	firewallUnpunch ${config["CONN_DEST"]}
	updateConfig "CONN_DEST" $nowhere
	log "Successfully disconnected.\n"
}


# Usage:  connect
# Before: Nothing.
# After:  A connection to Nord is up.
function connect () {
	[[ ${config["CONF_LOADED"]} -ne 1 ]] && checkSetup && loadConfig
	nmcli connection show --active | grep nordvpn &>/dev/null
	if [[ $? -eq 0 ]]
	then
		vlog "There is already a VPN connection up.\n"
		log "Already connected to ${config["CONN_DEST"]}.\n"
		return 0
	fi
	if [[ -z $(cat $AUTH_FILE) ]]
	then
		elog "No credentials stored.\n"
		getLogin
		elog "Now try to connect again.\n"
		return 0
	fi
	getRecommendedServer
	updateConfig "CONN_DEST" $retvar
	# If credentials are not stored, request them.
	if [[ ! -f $AUTH_FILE ]]; then
		getLogin
	fi
	# Connect to NordVPN
	vlog "Connecting to NordVPN... \n"
	# Punch hole in firewall
	firewallPunch ${config["CONN_DEST"]}
	dest="${config["CONN_DEST"]}.nordvpn.com.$CONN_TYPE"
	
	code=0
	output=$( $nmcli connection import type openvpn file \
		"$OVPN_DIR/ovpn_${config["CONN_TYPE"]}/$dest.ovpn" )
	[[ $? != 0 ]] && code=1; vlog "${output[@]}\n"
	output=$( $nmcli connection modify $dest vpn.user-name ${config["USERNAME"]} )
	[[ $? != 0 ]] && code=1; vlog "${output[@]}\n"
	output=$( $nmcli connection up $dest passwd-file $AUTH_FILE )
	[[ $? != 0 ]] && code=1; vlog "${output[@]}\n"
	
	if [[ $code != 0 ]]
	then
		elog "Something came up."
		disconnect
		return 1
	fi
	log "Successfully connected to ${config["CONN_DEST"]}.\n"
	(2>/dev/null getRecommendedServer) &
}

# Usage:  setup
# Before: Nothing.
# After:  A configuration file has been created,
#         .ovpn files have been downloaded and extracted.
function setup () {
	log "Setting up $PROGNAME... "

	# Remove any unzipped vpn files; they can be re-unzipped later.
	# Unzipping is unexpensive in terms of time.
	if [[ -e $OVPN_DIR ]]
	then
		rm -r $OVPN_DIR
	fi
	mkdir -p $DATA_DIR $CONF_DIR $CACHE_DIR

	# Set up default config
	cat $(dirname $0)/nord.conf.default > $CONF_FILE
	
	# If the cache has vpn files zipped, they might be old.
	# Let the user decide if they need updating.
	# If no cache, the zip file is downloaded.
	if [[ -e $VPN_FILES ]]
	then
		log "\nCached vpn files found. Do you want to use them? [y/n] "
		answered=0
		while [[ answered -eq 0 ]]
		do
			read answer
			log "\n"
			if [[ $answer == "y" || $answer == "Y" ]]
			then
				answered=1
			elif [[ $answer == "n" || $answer == "N" ]]
			then
				answered=1
				rm -r $VPN_FILES
				$wget -O $VPN_FILES $VPN_FILE_URL
			else
				log "Incorrect answer. Do you want to use the cached files? [y/n] "
			fi
		done
	else
		$wget -O $VPN_FILES $VPN_FILE_URL
	fi

	# Extract zipfile.
	mkdir -p $OVPN_DIR
	$unzip -q $VPN_FILES -d $OVPN_DIR

	vlog "Done\n"
	return 0
}


# Usage:  checkLegalCountry x
# Before: Nothing.
# After:  Returns 0 if x is a country code, and
#          optionally a server number in that country.
#          Returns 1 otherwise.
function checkLegalCountry () {
	elog "This function \(checkLegalCoutry\) has not been implemented yet.\n"
	return 0
}


# Usage:  printHelp
# Before: Nothing.
# After:  A useful help message has been printed to stout.
function printHelp () {
	vlog "Printing help message... \n"
	log "\n"
	log " Usage: $PROGNAME [OPTION] [COMMAND [ARGUMENT]]\n"
	log "\n\n"
	log "   Commands [args]\n"
	log "\n"
	log "      setup           Downloads the required files\n"
	log "                         and takes care of some initial plumbing.\n"
	log "    connect [x]       Connect to the best NordVPN server, or to x\n"
	log "                         where x is a country code, or a country code\n"
	log "                         and numbers, together identifying a NordVPN server.\n"
	log " disconnect           Disconnect from NordVPN.\n"
	log "     config           Display all of your configurations.\n"
	log "        set x y       Set config item x to y.\n"
	log "                      Valid config items and their values:\n\n"
	log "                        killswitch [on|off]     Requires root access.\n"
	log "                        protocol   [tcp|udp]\n"
	log "                        obfuscated [on|off]\n"
	log "                        autostart  [on|off]\n"
	log "\n"
}


# Usage:  invalidParam
# Before: Nothing.
# After:  An error message is has been printed notifying the
#          user that the supplied argument is invalid.
#          Program exits with code 1.
function invalidParam () {
	elog "Invalid parameter!\n"
	exit 1
}



function main () {
	# Empty call, and startup loading.
	if [[ $# -eq 0 ]]
	then
		return 0
	fi

	# Parse command line options
	positional=()
	while [[ $# -gt 0 ]]
	do
		cmd=$1

		case $cmd in
			-v|--verbose)
				updateConfig "VERBOSE" 1 "nosave"
				loadConfig
				shift
				;;
			-vv|--very-verbose)
				updateConfig "VERBOSE" 1 "nosave"
				updateConfig "VVERBOSE" 1 "nosave"
				loadConfig
				shift
				;;
			c|connect)
				checkSetup
				if [[ -n $2 ]]
				then
					if [[ $(checkLegalCountry $2) -ne 0 ]]
					then
						log "Illegal country code."
						return 1
					fi
					updateConfig "CONN_DEST_COUNTRY" $2
				fi
				connect
				return 0
				;;
			d|disconnect)
				disconnect
				return 0
				;;
			login)
				getLogin
				return 0
				;;
			s|setup)
				setup
				return 0
				;;
			config)
				getConfig
				return 0
				;;
			set)
				shift # Remove "set" command
				if [[ -z $1 || -z $2 ]]
				then
					printHelp
					return 1
				fi
				vlog "Setting $1 to $2.\n"
				key=$1
				val=$2
				if   [[ $2 == "on"  ]]; then val=1
				elif [[ $2 == "off" ]]; then val=0
				elif [[ $2 == 0     ]]; then val=0
				elif [[ $2 == 1     ]]; then val=1
				fi

				if   [[ $1 == "country" ]]; then key="conn_dest_country"; fi
				if [[ $key == "verbose" && $val -eq 0 ]]; then (updateConfig "VVERBOSE" 0); fi
				if [[ $key == "vverbose" && $val -eq 0 ]]; then (updateConfig "VVERBOSE" 0); fi
				if [[ $1 == "protocol" ]]; then
					key="conn_type"
					[[ ! ( $2 == "tcp" || $2 == "TCP" ||
						   $2 == "udp" || $2 == "UDP" ) ]] && invalidParam
					vvlog "Configuring protocol $val, but transforming it to "
					val=$(toLower $val)
					vvlog "$val.\n"
				fi
				if [[ $1 == "autostart" ]]
				then
					elog "autostarting $PROGNAME has not been implemented yet.\n"
					return 1
				fi

				# Special cases
				if [[ $1 == "killswitch" ]]
				then
					killswitch $2
					return 0
				fi

				updateConfig $(toUpper $key) $val
				return 0
				;;
			command)
				shift
				cmd=$1
				shift
				$cmd $@
				return 0
				;;
			*)
				printHelp
				return 1
				;;
		esac
	done


}

main $@


# TODO list
# - Add obfuscation
# - Add selection of country
# - Add periodical update of best servers
# - Change firewalld to iptables
# - 
# - 
# - 
# - 
# - 
# - 
# - 
# - 


