#!/bin/sh
#  ___ _                 _     _    _ _
# / __| |___  _ _ _  ___| |_  | |  (_) |_ ___
# \__ \ / / || | ' \/ -_)  _| | |__| |  _/ -_)
# |___/_\_\\_, |_||_\___|\__| |____|_|\__\___|
#          |__/
#
#   Skynet Lite by Willem Bartels
#   IP Blocking For ASUS Routers Using IPSet
#   https://github.com/wbartels/IPSet_ASUS_Lite
#
#   Code is based on Skynet By Adamm
#   Advanced IP Blocking For ASUS Routers Using IPSet
#   https://github.com/Adamm00/IPSet_ASUS
#   This script will always be open source and free to use
#
#
# Installation:
# curl https://raw.githubusercontent.com/wbartels/IPSet_ASUS_Lite/master/firewall.sh --output /jffs/scripts/firewall && chmod 755 /jffs/scripts/firewall && sh /jffs/scripts/firewall
#
# Commands:
# firewall
# firewall 10.0.0.0
# firewall fresh
# firewall frequency
# firewall entries
# firewall warning
# firewall error
# firewall update
# firewall reset
# firewall uninstall
# firewall help
#
# Readme:
# The cron job is started every 15 minutes.
# By default the set update process is started after 4 cycles = 1 hour.
# This value can be overruled per set with the {n} tag.
# In case of a download error, this set is temporarily fixed to 1 cycle until a successful download.
# Both the <comment> and {n} tag are optional.
# The order of the url and tags are not important, but need to be on the same line.
#
# The other lists (ip, domain and asn) can contain multiple items per list.
# The items on these lists must be separated with a space, tab or newline.
# blacklist_ip, blacklist_domain, blacklist_asn and whitelist_ip can optional use one <comment> tag per list.
#


###################
#- Configuration -#
###################


filtertraffic="all"		# inbound | outbound | all
logmode="enabled"		# enabled | disabled
loginvalid="disabled"	# enabled | disabled
debugupdate="enabled"	# enabled | disabled


blacklist_set="		<alienvault>			https://reputation.alienvault.com/reputation.generic  {4}
					<binarydefense>			https://www.binarydefense.com/banlist.txt  {4}
					<blocklist.de>			https://lists.blocklist.de/lists/all.txt  {1}
					<blocklist.net.ua>		https://iplists.firehol.org/files/blocklist_net_ua.ipset  {1}
					<cleantalk>				https://iplists.firehol.org/files/cleantalk_7d.ipset  {1}
					<dshield>				https://iplists.firehol.org/files/dshield_1d.netset  {4}
					<greensnow>				https://iplists.firehol.org/files/greensnow.ipset  {1}
					<maxmind>				https://www.maxmind.com/en/high-risk-ip-sample-list  {16}
					<myip>					https://www.myip.ms/files/blacklist/csf/latest_blacklist.txt  {4}
					<spamhaus_drop>			https://www.spamhaus.org/drop/drop.txt  {16}
					<spamhaus_edrop>		https://www.spamhaus.org/drop/edrop.txt  {16}
					<talosintel>			https://iplists.firehol.org/files/talosintel_ipfilter.ipset  {1}
					<tor_exits>				https://iplists.firehol.org/files/tor_exits.ipset  {1}"
blacklist_ip=""
blacklist_domain=""
blacklist_asn=""
whitelist_ip=""
whitelist_domain=""


##########################
#- End of configuration -#
##########################


command="$1"
option="$2"
throttle=0
updatecount=0
iotblocked="disabled"
version="2.01b"
useragent="Skynet-Lite/$version (Linux) https://github.com/wbartels/IPSet_ASUS_Lite"
lockfile="/tmp/var/lock/skynet.lock"

dir_skynet="/tmp/skynet"
dir_cache="$dir_skynet/cache"
dir_debug="$dir_skynet/debug"
dir_filtered="$dir_skynet/filtered"
dir_reload="$dir_skynet/reload"
dir_sleep="$dir_skynet/sleep"
dir_system="$dir_skynet/system"
dir_temp="$dir_skynet/temp"
dir_update="$dir_skynet/update"
mkdir -p "$dir_cache" "$dir_debug" "$dir_filtered" "$dir_reload"
mkdir -p "$dir_sleep" "$dir_system" "$dir_temp" "$dir_update"


if ! ipset list -n Skynet-Master >/dev/null 2>&1; then
	command="reset"
	option=""
fi


if [ "$(nvram get wan0_proto)" = "pppoe" ]; then
	iface="ppp0"
else
	iface="$(nvram get wan0_ifname)"
fi


###############
#- Functions -#
###############


unload_IPTables() {
	iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j DROP 2>/dev/null
	iptables -t raw -D PREROUTING -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
	iptables -t raw -D OUTPUT -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
	iptables -D SSHBFP -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j SET --add-set Skynet-Blacklist src 2>/dev/null
	iptables -D SSHBFP -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	ip6tables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -D logdrop -m state --state NEW -m limit --limit 4/sec -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	ip6tables -D logdrop -m state --state NEW -m limit --limit 4/sec -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
}


load_IPTables() {
	local pos1=
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
		iptables -t raw -I PREROUTING -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j DROP 2>/dev/null
	fi
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
		iptables -t raw -I PREROUTING -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
		iptables -t raw -I OUTPUT -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
	fi
	if [ "$(nvram get sshd_enable)" = "1" ] && [ "$(nvram get sshd_bfp)" = "1" ] && [ "$(uname -o)" = "ASUSWRT-Merlin" ] && [ "$(nvram get switch_wantag)" != "movistar" ]; then
		pos1="$(iptables --line -nL SSHBFP | grep -F "seconds: 60 hit_count: 4" | grep -E 'DROP|logdrop' | awk '{print $1}')"
		iptables -I SSHBFP "$pos1" -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j SET --add-set Skynet-Blacklist src 2>/dev/null
		iptables -I SSHBFP "$pos1" -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	fi
}


unload_LogIPTables() {
	iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -t raw -D PREROUTING -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -t raw -D OUTPUT -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -D logdrop -m state --state NEW -j LOG --log-prefix "[BLOCKED - INVALID] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -D FORWARD -i br0 -m set --match-set Skynet-IOT src ! -o tun2+ -j LOG --log-prefix "[BLOCKED - IOT] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
}


load_LogIPTables() {
	local pos2= pos3= pos4= pos5=
	if [ "$logmode" = "enabled" ]; then
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
			pos2="$(iptables --line -nL PREROUTING -t raw | grep -F "Skynet-Master src" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos2" -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
			pos3="$(iptables --line -nL PREROUTING -t raw | grep -F "Skynet-Master dst" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos3" -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
			pos4="$(iptables --line -nL OUTPUT -t raw | grep -F "Skynet-Master dst" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I OUTPUT "$pos4" -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
		if [ "$(nvram get fw_log_x)" = "drop" ] || [ "$(nvram get fw_log_x)" = "both" ] && [ "$loginvalid" = "enabled" ]; then
			iptables -I logdrop -m state --state NEW -j LOG --log-prefix "[BLOCKED - INVALID] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
		if [ "$iotblocked" = "enabled" ]; then
			pos5="$(iptables --line -nL FORWARD | grep -F "Skynet-IOT" | grep -F "DROP" | awk '{print $1}')"
			iptables -I FORWARD "$pos5" -i br0 -m set --match-set Skynet-IOT src ! -o tun2+ -j LOG --log-prefix "[BLOCKED - IOT] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
	fi
}


unload_IPSets() {
	ipset -q destroy Skynet-Master
	ipset -q destroy Skynet-Blacklist
	ipset -q destroy Skynet-Domain
	ipset -q destroy Skynet-ASN
	ipset -q destroy Skynet-Temp
	ipset -q destroy Skynet-Whitelist
	ipset -n list | filter_Skynet_Set | xargs -I setname ipset -q destroy setname
}


lookup_Domain() {
	set -o pipefail; nslookup "$1" 2>/dev/null | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | awk 'NR>2'
	if [ $? -ne 0 ]; then log_Skynet "[*] nslookup can't resolve $1"; fi
}


strip_Domain() {
	grep -Eo 'https?://\S+' | cut -d'/' -f3
}


filter_Domain() {
	awk '{gsub("<.+>", ""); print}' | grep -Eo '\b(([a-z](-?[a-z0-9])*)\.)+[a-z]{2,}\b'
}


filter_URL() {
	grep -Eo 'https?://\S+'
}


filter_URL_Line() {
	grep -E 'https?://\S+'
}


filter_IP_CIDR() {
	grep -Eo '\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3}(\/(3[0-2]|[1-2][0-9]|[0-9]))?\b'
}


filter_PrivateIP() {
	# https://regex101.com/r/vDjcX3/1
	grep -Ev '^(0\.|10\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|127\.|169\.254\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.0\.0\.|192\.0\.2\.|192\.168\.|198\.1[8-9]\.|198\.51\.100\.|203\.0\.113\.|2(2[4-9]|[3-4][0-9]|5[0-5])\.)'
}


filter_IP_Line() {
	grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
}


is_IP() {
	grep -Eo '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3}$'
}


filter_ASN() {
	grep -Eo 'AS[1-9][0-9]{2,9}'
}


filter_Comment() {
	grep -Eo '<.+>' | tr -d '<>' | tr ',' ';'
}


filter_Update_Cycles() {
	grep -Eo '\{[1-9][0-9]*\}' | tr -d '{}'
}


filter_Skynet() {
	grep -E '^Skynet-'
}


filter_Skynet_Set() {
	grep -E '^Skynet-[0-9a-f]{24}'
}


curl_Error() {
	case "$1" in
		1)  echo -n "Unsupported protocol" ;;
		2)  echo -n "Failed initialization" ;;
		3)  echo -n "URL malformat" ;;
		4)  echo -n "Not built in" ;;
		5)  echo -n "Couldn't resolve proxy" ;;
		6)  echo -n "Couldn't resolve host" ;;
		7)  echo -n "Couldn't connect" ;;
		8)  echo -n "Weird server reply" ;;
		9)  echo -n "Remote access denied" ;;
		18) echo -n "Partial file" ;;
		22) echo -n "HTTP error" ;;
		23) echo -n "Write error" ;;
		26) echo -n "Read error" ;;
		27) echo -n "Out of memory" ;;
		28) echo -n "Connection timed out" ;;
		33) echo -n "Range error" ;;
		35) echo -n "SSL connect error" ;;
		36) echo -n "Bad download resume" ;;
		47) echo -n "Too many redirects" ;;
		52) echo -n "Empty reply from server" ;;
		55) echo -n "Send error" ;;
		56) echo -n "Receive error" ;;
		60) echo -n "Peer failed verification" ;;
		61) echo -n "Bad content encoding" ;;
		*)  echo -n "Error $1 returned by curl" ;;
	esac
}


log_Skynet() {
	logger -t skynet "$1"
	echo " $1" >&2
	local type="$(echo "$1" | cut -c1-3)"
	if [ "$type" = "[!]" ]; then echo "$(date '+%b %d %T') | $(echo "$1" | cut -c5-)" >> "$dir_skynet/warning.log"; fi
	if [ "$type" = "[*]" ]; then echo "$(date '+%b %d %T') | $(echo "$1" | cut -c5-)" >> "$dir_skynet/error.log"; fi
}


log_Tail() {
	touch "$1"
	if [ $(wc -l < "$1") -ge 725 ]; then
		tail -n 675 "$1" > "$dir_temp/log" && mv -f "$dir_temp/log" "$1"
	fi
}


lookup_Comment_Init() {
	local comment=$(echo "$whitelist_ip" | filter_Comment); if [ -z "$comment" ]; then comment="whitelist"; fi; echo "Skynet-Whitelist,$comment" > "$dir_temp/lookup.csv"
	comment=$(echo "$blacklist_ip" | filter_Comment); if [ -z "$comment" ]; then comment="blacklist_ip"; fi; echo "Skynet-Blacklist,$comment" >> "$dir_temp/lookup.csv"
	comment=$(echo "$blacklist_domain" | filter_Comment); if [ -z "$comment" ]; then comment="blacklist_domain"; fi; echo "Skynet-Domain,$comment" >> "$dir_temp/lookup.csv"
	comment=$(echo "$blacklist_asn" | filter_Comment); if [ -z "$comment" ]; then comment="blacklist_asn"; fi; echo "Skynet-ASN,$comment" >> "$dir_temp/lookup.csv"
}


lookup_Comment() {
	awk -F, -v setname="$1" '$1 == setname {print $2}' "$dir_temp/lookup.csv"
}


formatted_Time() {
	if [ $1 -lt 86400 ]; then
		printf '%02d:%02d' $(($1/3600)) $(($1%3600/60))
	elif [ $1 -lt 172800 ]; then
		printf '1 day %02d:%02d' $(($1%86400/3600)) $(($1%3600/60))
	else
		printf '%d days %02d:%02d' $(($1/86400)) $(($1%86400/3600)) $(($1%3600/60))
	fi
}


formatted_File_Age() {
	formatted_Time $(($(date +%s) - $(date +%s -r "$1" 2>/dev/null || echo $start_time)))
}


file_Age() {
	echo $(($(date +%s) - $(date +%s -r "$1" 2>/dev/null || echo $start_time)))
}


script_Unmodified() {
	if [ "$1" = "timestamp" ]; then date +%s -r '/jffs/scripts/firewall' > "$dir_system/firewall_timestamp"; return; fi
	[ "$(date +%s -r '/jffs/scripts/firewall')" = "$(head -1 "$dir_system/firewall_timestamp" 2>/dev/null)" ]
}


update_Counter() {
	local n=$(head -1 "$1" 2>/dev/null)
	echo $((n + 1)) | tee "$1"
}


rand() {
	local min=$1 max=$2
	echo $((min + $(printf '%d' 0x$(openssl rand 2 -hex)) * (max - min + 1) / 65025))
}


header() {
	if [ "$option" = "cru" ]; then return; fi
	clear
	sed -n '2,7s/#//p' "$0"
	echo " Skynet Lite $version by Willem Bartels"
	echo " Code is based on Skynet By Adamm"
	echo
	if [ -n "$1" ] || [ -n "$2" ]; then
		printf "-----------------------------------------------------------\n"
		printf " %-25s  %30s\n" "$1" "$2"
		printf "-----------------------------------------------------------\n"
	fi
}


footer() {
	if [ "$option" = "cru" ]; then return; fi
	printf "-----------------------------------------------------------\n"
	printf " %-25s  %30s\n\n" \
		"Uptime $(formatted_File_Age "$dir_system/installtime")" \
		"$(if [ $(ls -1 "$dir_reload" | wc -l) -ge 1 ]; then echo "[i] Failed download queued"
		elif [ $(ls -1 "$dir_sleep" | wc -l) -ge 1 ]; then echo "[i] Download sleep"; fi)"
}


load_Whitelist() {
	if [ $((updatecount % 48)) -ne 0 ]; then return; fi
	log_Skynet "[i] Update $(lookup_Comment 'Skynet-Whitelist')"
	local cache= curl_exit= domain= http_code= n=0 temp= url=
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net comment
	# Whitelist router and reserved IP addresses:
	echo "add Skynet-Temp $(nvram get wan0_ipaddr) comment \"Whitelist: wan0_ipaddr\"
		add Skynet-Temp $(nvram get wan0_realip_ip) comment \"Whitelist: wan0_realip_ip\"
		add Skynet-Temp $(nvram get wan0_gateway) comment \"Whitelist: wan0_gateway\"
		add Skynet-Temp $(nvram get wan0_xgateway) comment \"Whitelist: wan0_xgateway\"
		add Skynet-Temp $(nvram get wan0_dns | awk '{print $1}') comment \"Whitelist: wan0_dns\"
		add Skynet-Temp $(nvram get wan0_dns | awk '{print $2}') comment \"Whitelist: wan0_dns\"
		add Skynet-Temp $(nvram get dhcp_dns1_x) comment \"Whitelist: dhcp_dns1_x\"
		add Skynet-Temp $(nvram get dhcp_dns2_x) comment \"Whitelist: dhcp_dns2_x\"
		add Skynet-Temp 0.0.0.0/8 comment \"Whitelist: This network\"
		add Skynet-Temp 10.0.0.0/8 comment \"Whitelist: Private network\"
		add Skynet-Temp 100.64.0.0/10 comment \"Whitelist: Carrier-grade NAT\"
		add Skynet-Temp 127.0.0.0/8 comment \"Whitelist: Loopback\"
		add Skynet-Temp 169.254.0.0/16 comment \"Whitelist: Link local\"
		add Skynet-Temp 172.16.0.0/12 comment \"Whitelist: Private network\"
		add Skynet-Temp 192.0.0.0/24 comment \"Whitelist: IETF protocol assignments\"
		add Skynet-Temp 192.0.2.0/24 comment \"Whitelist: TEST-NET-1\"
		add Skynet-Temp 192.168.0.0/16 comment \"Whitelist: Private network\"
		add Skynet-Temp 198.18.0.0/15 comment \"Whitelist: Network interconnect device benchmark testing\"
		add Skynet-Temp 198.51.100.0/24 comment \"Whitelist: TEST-NET-2\"
		add Skynet-Temp 203.0.113.0/24 comment \"Whitelist: TEST-NET-3\"
		add Skynet-Temp 224.0.0.0/3 comment \"Whitelist: Multicast/reserved/limited broadcast\"" | tr -d '\t' | filter_IP_Line | ipset restore -!
	# Whitelist ip:
	echo "$whitelist_ip" | filter_IP_CIDR | filter_PrivateIP | awk '{printf "add Skynet-Temp %s comment \"Whitelist: %s\"\n", $1, $1}' | ipset restore -!
	# Whitelist domain:
	whitelist_domain="$whitelist_domain $(echo "$blacklist_set $(nvram get firmware_server)" | strip_Domain)
		internic.net
		ipinfo.io
		raw.githubusercontent.com
		dns.adguard.com
		dns.google
		dns.opendns.com
		dns.quad9.net
		one.one.one.one
		$(nvram get ntp_server0)
		$(nvram get ntp_server1)"
	for domain in $(echo "$whitelist_domain" | filter_Domain | awk '!x[$0]++'); do
		lookup_Domain "$domain" | filter_PrivateIP | awk -v domain="$domain" '{printf "add Skynet-Temp %s comment \"Whitelist: %s\"\n", $1, domain}' | ipset restore -! &
		n=$((n + 1)); if [ $((n % 50)) -eq 0 ]; then wait; fi
	done
	wait
	# Whitelist root hints:
	url="http://www.internic.net/domain/named.root"
	temp="$dir_temp/named.root"; touch "$temp"
	cache="$dir_cache/named.root"
	if http_code=$(curl -sf --location --user-agent "$useragent" --connect-timeout 10 --max-time 180 --limit-rate "$throttle" --output "$temp" --write-out "%{http_code}" "$url" --remote-time --time-cond "$cache") && [ "$http_code" = "200" ]; then
		mv -f "$temp" "$cache"
	fi
	if [ -f "$cache" ]; then
		filter_IP_CIDR < "$cache" | filter_PrivateIP | awk '{printf "add Skynet-Temp %s comment \"Whitelist: Root hints\"\n", $1}' | ipset restore -!
	fi
	rm -f "$temp";
	ipset swap "Skynet-Whitelist" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
}


load_Blacklist() {
	if script_Unmodified; then return; fi
	log_Skynet "[i] Update $(lookup_Comment 'Skynet-Blacklist')"
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net comment
	echo "$blacklist_ip" | filter_IP_CIDR | filter_PrivateIP | awk '{printf "add Skynet-Temp %s comment \"Blacklist: %s\"\n", $1, $1}' | ipset restore -!
	ipset swap "Skynet-Blacklist" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
}


load_Domain() {
	if [ $((updatecount % 48)) -ne 0 ]; then return; fi
	log_Skynet "[i] Update $(lookup_Comment 'Skynet-Domain')"
	local domain= n=0
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net comment
	for domain in $(echo "$blacklist_domain" | filter_Domain); do
		lookup_Domain "$domain" | filter_PrivateIP | awk -v domain="$domain" '{printf "add Skynet-Temp %s comment \"Blacklist: %s\"\n", $1, domain}' | ipset restore -! &
		n=$((n + 1)); if [ $((n % 50)) -eq 0 ]; then wait; fi
	done
	wait
	ipset swap "Skynet-Domain" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
}


load_ASN() {
	if [ $((updatecount % 48)) -ne 0 ] && [ ! -f "$dir_reload/asn" ]; then return; fi
	log_Skynet "[i] Update $(lookup_Comment 'Skynet-ASN')"
	local asn= n=0
	rm -f "$dir_reload/asn"
	ipset -q destroy "Skynet-Temp"
	ipset create "Skynet-Temp" hash:net comment
	for asn in $(echo "$blacklist_asn" | filter_ASN); do
		(
			url="https://ipinfo.io/$asn"
			temp="$dir_temp/$asn"
			http_code=$(curl -sf --location --user-agent "$useragent" --connect-timeout 10 --max-time 180 --limit-rate "$throttle"  --output "$temp" --write-out "%{http_code}" "$url"); curl_exit=$?
			if [ $curl_exit -eq 0 ]; then
				filter_IP_CIDR < "$temp" | awk '!x[$0]++' | filter_PrivateIP | awk -v asn="$asn" '{printf "add Skynet-Temp %s comment \"Blacklist: %s\"\n", $1, asn}' | ipset restore -!
			elif [ "$http_code" = "429" ]; then
				log_Skynet "[*] Download error HTTP/429 Too many requests $url"
				touch "$dir_temp/asn_too_many_requests"
				rm -f "$dir_reload/asn"
			else
				log_Skynet "[*] Download error HTTP/$http_code $(curl_Error $curl_exit) $url"
				touch "$dir_reload/asn"
			fi
			rm -f "$temp"
		) &
		n=$((n + 1)); if [ $((n % 10)) -eq 0 ]; then wait; fi
		if [ -f "$dir_reload/asn" ] || [ -f "$dir_temp/asn_too_many_requests" ]; then ipset destroy "Skynet-Temp"; return; fi
	done
	wait
	if [ -f "$dir_reload/asn" ] || [ -f "$dir_temp/asn_too_many_requests" ]; then ipset destroy "Skynet-Temp"; return; fi
	ipset swap "Skynet-ASN" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
}


load_Set() {
	log_Skynet "[i] Update $comment"
	if ! ipset list -n "$setname" >/dev/null 2>&1; then
		ipset create "$setname" hash:net maxelem 524288 comment
		ipset add Skynet-Master "$setname" comment "$comment"
	fi
	diff "$filtered_cache" "$filtered_temp" > "$dir_temp/diff"
	grep -E '^\+[0-9]' < "$dir_temp/diff" | cut -c2- > "$dir_temp/add"
	grep -E '^-[0-9]' < "$dir_temp/diff" | cut -c2- > "$dir_temp/del"
	awk -v setname="$setname" -v comment="$comment" '{printf "add %s %s comment \"Blacklist: %s\"\n", setname, $1, comment}' "$dir_temp/add" | ipset restore -!
	awk -v setname="$setname" '{printf "del %s %s\n", setname, $1}' "$dir_temp/del" | ipset restore -!
	if [ "$debugupdate" = "enabled" ]; then
		printf "%s | %6s | %7s | %7s |\n" \
			"$(date '+%b %d %T')" \
			"$(wc -l < "$filtered_temp")" \
			"-$(wc -l < "$dir_temp/del")" \
			"+$(wc -l < "$dir_temp/add")" >> "$dir_debug/$comment.log"
		log_Tail "$dir_debug/$comment.log"
	fi
	update_Counter "$dir_update/$setname" >/dev/null
	rm -f "$dir_temp/diff" "$dir_temp/add" "$dir_temp/del"
}


compare_Set() {
	{
		case "$url" in
			*.zip)			unzip -p "$temp";;
			*.tgz|*.tar.gz)	tar -xzOf "$temp";;
			*)				gunzip -c "$temp" 2>/dev/null || cat "$temp";;
		esac
	} | filter_IP_CIDR | filter_PrivateIP | sort -u > "$filtered_temp"
	if [ ! -f "$filtered_cache" ]; then
		touch "$filtered_cache"
	fi
	cmp -s "$filtered_cache" "$filtered_temp"
}


download_Set() {
	local cache= comment= curl_exit= dir= filtered_cache= filtered_temp= http_code= line= list= lookup= setname= temp= update_cycles= url=
	echo "$blacklist_set" | filter_URL_Line > "$dir_temp/blacklist_set"

	while IFS= read -r line; do
		url=$(echo "$line" | filter_URL)
		comment=$(echo "$line" | filter_Comment)
		update_cycles=$(echo "$line" | filter_Update_Cycles)
		setname="Skynet-$(echo -n "$url" | md5sum | cut -c1-24)"

		if [ -z "$comment" ]; then
			comment=$(filter_Comment "<$(basename "$url")>")
		fi
		echo "$setname,$comment" >> "$dir_temp/lookup.csv"
		if [ -z "$update_cycles" ]; then
			update_cycles=4
		fi
		if [ -f "$dir_reload/$setname" ] || ! script_Unmodified; then
			update_cycles=1
			rm -f "$dir_reload/$setname"
		fi
		if [ $((updatecount % update_cycles)) -ne 0 ]; then
			continue
		fi
		if [ -f "$dir_sleep/$setname" ] && [ $(file_Age "$dir_sleep/$setname") -lt 14400 ]; then
			log_Skynet "[!] Sleep $(formatted_Time $((14400 - $(file_Age "$dir_sleep/$setname")))) $comment"
			continue
		fi
		rm -f "$dir_sleep/$setname"

		temp="$dir_temp/${setname}_unfiltered"; touch "$temp"
		cache="$dir_cache/$setname"
		filtered_temp="$dir_temp/${setname}_filtered"
		filtered_cache="$dir_filtered/$setname"
		http_code=$(curl -sf --location --header "Accept-encoding: gzip" --user-agent "$useragent" --connect-timeout 10 --max-time 180 --limit-rate "$throttle" --output "$temp" --write-out "%{http_code}" "$url" --remote-time --time-cond "$cache"); curl_exit=$?
		if [ $curl_exit -eq 0 ]; then
			if [ "$http_code" = "304" ]; then
				log_Skynet "[i] Fresh $comment"
			elif compare_Set && ipset -n list "$setname" >/dev/null 2>&1; then
				log_Skynet "[!] Redownload $comment"
				mv -f "$temp" "$cache"
			else
				load_Set
				mv -f "$temp" "$cache"
				mv -f "$filtered_temp" "$filtered_cache"
			fi
		elif [ "$http_code" = "429" ]; then
			log_Skynet "[*] Download error HTTP/429 Too many requests $url"
			touch "$dir_sleep/$setname"
		else
			log_Skynet "[*] Download error HTTP/$http_code $(curl_Error $curl_exit) $url"
			touch "$dir_reload/$setname"
		fi
		rm -f "$temp" "$filtered_temp"
	done < "$dir_temp/blacklist_set"
	sort -t, -k2 < "$dir_temp/lookup.csv" > "$dir_system/lookup.csv"

	if script_Unmodified; then return; fi

	# Unload unlisted sets
	list=$(awk -F, '{print $1}' "$dir_system/lookup.csv" | filter_Skynet_Set)
	for setname in $(ipset list Skynet-Master | filter_Skynet_Set | awk '{print $1}'); do
		if ! echo "$list" | grep -q "$setname"; then
			ipset -q del "Skynet-Master" "$setname"
			ipset -q destroy "$setname"
		fi
	done

	# Cleanup directories
	for dir in "$dir_cache" "$dir_filtered" "$dir_reload" "$dir_sleep" "$dir_update"; do
		cd "$dir"
		for setname in $(ls -1t | filter_Skynet_Set); do
			if ! echo "$list" | grep -q "$setname"; then
				rm -f "$dir/$setname"
			fi
		done
	done
}


############################
#- Initialize Skynet Lite -#
############################


i=0
while [ "$(nvram get ntp_ready)" = "0" ]; do
	if [ $i -eq 0 ]; then log_Skynet "[i] Waiting for NTP to sync..."; fi
	if [ $i -eq 300 ]; then log_Skynet "[*] NTP failed to start after 5 minutes - Please fix immediately!"; echo; exit 1; fi
	i=$((i + 1)); sleep 1
done
start_time=$(($(date +%s) - i))


if [ "$command" = "update" ] || [ "$command" = "reset" ]; then
	for i in 1 2 3 4 5 6; do
		if ping -q -w1 -c1 google.com >/dev/null 2>&1; then break; fi
		if ping -q -w1 -c1 github.com >/dev/null 2>&1; then break; fi
		if ping -q -w1 -c1 amazon.com >/dev/null 2>&1; then break; fi
		if [ $i -eq 1 ]; then log_Skynet "[!] Waiting for internet connectivity..."; fi
		if [ $i -eq 6 ]; then log_Skynet "[*] Internet connectivity error"; echo; exit 1; fi
		sleep 9
	done
fi


if [ "$command" = "update" ] && [ "$option" = "cru" ]; then
	throttle="1M"
	updatecount=$(update_Counter "$dir_system/updatecount")
	execution_time=$(($(date +%s) - start_time))
	if [ $execution_time -ge 0 ] && [ $execution_time -lt 10 ]; then
		sleep $((10 - execution_time))
	fi
fi


exec 99>"$lockfile"
if ! flock -n 99; then
	echo " [i] Skynet Lite is locked, please try again later"; echo; exit 1
fi


cp "$dir_system/lookup.csv" "$dir_temp/lookup.csv"
unset i execution_time


#######################
#- Start Skynet Lite -#
#######################


ip=$(echo "$command" | is_IP) || ip="noip"
case "$command" in
	reset)
		header "Reset"
		log_Skynet "[i] Install"
		rm -f "$dir_cache/"* "$dir_debug/"* "$dir_filtered/"* "$dir_reload/"*
		rm -f "$dir_sleep/"* "$dir_system/"* "$dir_temp/"* "$dir_update/"*
		true > "$dir_skynet/warning.log"
		true > "$dir_skynet/error.log"
		touch "$dir_system/installtime"
		lookup_Comment_Init
		if [ "$0" != "/jffs/scripts/firewall" ]; then
			mv -f "$0" "/jffs/scripts/firewall"
			log_Skynet "[!] Skynet Lite moved to /jffs/scripts/firewall"
		fi
		if [ ! -f "/jffs/scripts/firewall-start" ]; then
			echo "#!/bin/sh
			sh /jffs/scripts/firewall" | tr -d '\t' > "/jffs/scripts/firewall-start"
			chmod 755 "/jffs/scripts/firewall-start"
		elif [ -f "/jffs/scripts/firewall-start" ] && ! grep -q "/jffs/scripts/firewall" "/jffs/scripts/firewall-start"; then
			chmod 755 "/jffs/scripts/firewall-start"
			echo "sh /jffs/scripts/firewall" >> "/jffs/scripts/firewall-start"
		fi
		rand=$(rand 1 14)
		cru d Skynet_update
		cru a Skynet_update "$((rand)),$((rand + 15)),$((rand + 30)),$((rand + 45)) * * * * nice -n 19 sh /jffs/scripts/firewall update cru"
		unload_IPTables
		unload_LogIPTables
		unload_IPSets
		echo 'create Skynet-Master list:set size 64 comment counters
			create Skynet-Blacklist hash:net comment
			create Skynet-Domain hash:net comment
			create Skynet-ASN hash:net comment
			create Skynet-Whitelist hash:net comment
			add Skynet-Master Skynet-Blacklist comment "blacklist_ip"
			add Skynet-Master Skynet-Domain comment "blacklist_domain"
			add Skynet-Master Skynet-ASN comment "blacklist_asn"' | tr -d '\t' | ipset restore -!
		load_IPTables
		load_LogIPTables
		load_Whitelist
		load_Blacklist
		load_Domain
		load_ASN
		download_Set
		script_Unmodified "timestamp"
		footer
	;;


	update)
		header "Update"
		lookup_Comment_Init
		load_Whitelist
		load_Blacklist
		load_Domain
		load_ASN
		download_Set
		script_Unmodified "timestamp"
		footer
	;;


	uninstall)
		header "Uninstall"
		log_Skynet "[*] Uninstall Skynet Lite..."
		if [ -f "/jffs/scripts/firewall-start" ]; then
			chmod 755 "/jffs/scripts/firewall-start"
			config=$(grep -v "/jffs/scripts/firewall" "/jffs/scripts/firewall-start")
			echo "$config" > "/jffs/scripts/firewall-start"
		fi
		cru d Skynet_update
		unload_IPTables
		unload_LogIPTables
		unload_IPSets
		rm -fr "$dir_skynet"
		rm -f "$lockfile" "$0"
		echo " [i] Skynet Lite has been successfully uninstalled"; echo; exit 0
	;;


	"$ip")
		header "Search for $ip"
		while IFS=, read -r setname comment; do
			if ipset -q test "$setname" "$ip"; then
				echo " [*] $comment"
			else
				echo " [ ] $comment"
			fi
		done < "$dir_system/lookup.csv"
		footer
	;;


	warning)
		header
		if [ -f "$dir_skynet/warning.log" ] && [ $(wc -l < "$dir_skynet/warning.log") -ge 1 ]; then
			cat "$dir_skynet/warning.log"
		else
			echo "Empty warning.log"
		fi
		echo
	;;


	error)
		header
		if [ -f "$dir_skynet/error.log" ] && [ $(wc -l < "$dir_skynet/error.log") -ge 1 ]; then
			cat "$dir_skynet/error.log"
		else
			echo "Empty error.log"
		fi
		echo
	;;


	fresh)
		header "Blacklist" "Client file age"
		true > "$dir_temp/file.csv"
		filter_Skynet_Set < "$dir_system/lookup.csv" | while IFS=, read -r setname comment; do
			age=$(file_Age "$dir_update/$setname")
			echo "$comment,$(formatted_Time "$age"),$age" >> "$dir_temp/file.csv"
		done
		sort -t, -k3n < "$dir_temp/file.csv" | awk -F, '{printf " %-40s  %15s\n", $1, $2}'
		footer
	;;


	frequency)
		header "Blacklist" "Average update time"
		true > "$dir_temp/file.csv"
		filter_Skynet_Set < "$dir_system/lookup.csv" | while IFS=, read -r setname comment; do
			n=$(head -1 "$dir_update/$setname" 2>/dev/null || echo 1)
			sec=$(($(file_Age "$dir_system/installtime") / n))
			echo "$comment,$(formatted_Time "$sec"),$sec" >> "$dir_temp/file.csv"
		done
		sort -t, -k3n < "$dir_temp/file.csv" | awk -F, '{printf " %-40s  %15s\n", $1, $2}'
		footer
	;;


	entries)
		header "List" "Number of entries"
		true > "$dir_temp/file.csv"
		while IFS=, read -r setname comment; do
			echo "$comment,$(ipset -t list "$setname" | grep -F 'Number of entries' | grep -Eo '[0-9]+')" >> "$dir_temp/file.csv"
		done < "$dir_system/lookup.csv"
		sort -t, -k2nr < "$dir_temp/file.csv" | awk -F, '{printf " %-40s  %15s\n", $1, $2}'
		footer
	;;


	help)
		header "Commands"
		echo " firewall"
		echo " firewall 10.0.0.0"
		echo " firewall fresh"
		echo " firewall frequency"
		echo " firewall entries"
		echo " firewall warning"
		echo " firewall error"
		echo " firewall update"
		echo " firewall reset"
		echo " firewall uninstall"
		echo " firewall help"
		footer
	;;


	*)
		header "Blacklist" "Packets blocked"
		true > "$dir_temp/file.csv"
		ipset list Skynet-Master | filter_Skynet | awk '{print $1","$3}' | while IFS=, read -r setname blocked; do
			echo "$(lookup_Comment "$setname"),$blocked" >> "$dir_temp/file.csv"
		done
		sort -t, -k2nr -k1,1 < "$dir_temp/file.csv" | awk -F, '{printf " %-40s  %15s\n", $1, $2}'
		footer
	;;
esac


rm -f "$dir_temp/"*
log_Tail "$dir_skynet/warning.log"
log_Tail "$dir_skynet/error.log"
