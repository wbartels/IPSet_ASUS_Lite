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
# firewall 1.1.1.1
# firewall fresh
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
# The other lists (ip, domain and asn) can contain multiple items per line.
# The items on these lists can be separated with a space, tab or newline.
#


###################
#- Configuration -#
###################


filtertraffic="all"		# inbound | outbound | all
logmode="enabled"		# enabled | disabled
loginvalid="disabled"	# enabled | disabled


blacklist_set="		<alienvault_reputation>			https://reputation.alienvault.com/reputation.generic  {4}
					<binarydefense_atif>			https://www.binarydefense.com/banlist.txt  {1}
					<blocklist_de>					https://lists.blocklist.de/lists/all.txt  {1}
					<blocklist_net_ua>				https://iplists.firehol.org/files/blocklist_net_ua.ipset  {1}
					<ciarmy>						https://cinsscore.com/list/ci-badguys.txt  {1}
					<cleantalk_7d>					https://iplists.firehol.org/files/cleantalk_7d.ipset  {4}
					<dshield>						https://iplists.firehol.org/files/dshield.netset  {4}
					<greensnow>						https://iplists.firehol.org/files/greensnow.ipset  {1}
					<maxmind_high_risk>				https://www.maxmind.com/en/high-risk-ip-sample-list  {12}
					<myip>							https://www.myip.ms/files/blacklist/csf/latest_blacklist.txt  {1}
					<spamhaus_drop>					https://www.spamhaus.org/drop/drop.txt  {12}
					<spamhaus_edrop>				https://www.spamhaus.org/drop/edrop.txt  {12}
					<talosintel>					https://iplists.firehol.org/files/talosintel_ipfilter.ipset  {4}
					<tor_exits>						https://check.torproject.org/exit-addresses  {1}"
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
updatecount="0"
throttle="0"
iotblocked="disabled"
version="1.14e"
useragent="Skynet-Lite/$version (Linux) https://github.com/wbartels/IPSet_ASUS_Lite"


dir_skynet="/tmp/skynet"
dir_cache1="$dir_skynet/cache1"
dir_cache2="$dir_skynet/cache2"
dir_reload="$dir_skynet/reload"
dir_system="$dir_skynet/system"
dir_temp="$dir_skynet/temp"
dir_update="$dir_skynet/update"
file_errorlog="$dir_skynet/error.log"
file_installtime="$dir_system/installtime"
file_updatecount="$dir_system/updatecount"
file_warninglog="$dir_skynet/warning.log"
mkdir -p "$dir_cache1" "$dir_cache2" "$dir_reload"
mkdir -p "$dir_system" "$dir_temp" "$dir_update"


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
	ipset list -n | filter_Skynet_Set | xargs -I setname ipset -q destroy setname
}


log_Skynet() {
	logger -t skynet "$1"
	echo " $1" >&2
	local type="$(echo "$1" | cut -c1-3)"
	if [ "$type" = "[!]" ]; then echo "$(date) | $(echo "$1" | cut -c5-)" >> "$file_warninglog"; fi
	if [ "$type" = "[*]" ]; then echo "$(date) | $(echo "$1" | cut -c5-)" >> "$file_errorlog"; fi
}


log_Tail() {
	touch "$1"
	tail -n 750 "$1" > "$dir_temp/log" && mv -f "$dir_temp/log" "$1"
}


domain_Lookup() {
	set -o pipefail; nslookup "$1" 2>/dev/null | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | awk 'NR>2'
	if [ $? -ne 0 ]; then
		log_Skynet "[*] nslookup can't resolve $1"
	fi
}


strip_Domain() {
	grep -oE 'https?://\S+' | cut -d'/' -f3 | awk '!x[$0]++'
}


filter_URL() {
	grep -oE 'https?://\S+'
}


filter_URL_Line() {
	grep -E 'https?://\S+'
}


filter_IP_CIDR() {
	grep -oE '\b((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3})(\/(3[0-2]|[12]?[0-9]))?\b'
}


filter_PrivateIP() {
	grep -vE '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)|(^0.)|(^169\.254\.)|(^22[4-9]\.)|(^23[0-9]\.)|(^255\.255\.255\.255)|(^8\.8\.8\.8)|(^8\.8\.4\.4)(^1\.1\.1\.1)|(^1\.0\.0\.1)'
}


filter_IP_Line() {
	grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
}


is_IP() {
	grep -oE '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3}$'
}


filter_ASN() {
	grep -oE 'AS[1-9][0-9]{2,9}'
}


filter_Word() {
	grep -oE '\b\S+\b'
}


filter_Comment() {
	grep -oE '<.+>' | tr -d '<>' | tr ' ' '_'
}


filter_Update_Cycles() {
	grep -oE '\{[0-9]+\}' | tr -d '{}'
}


filter_Skynet() {
	grep  -E '^Skynet-'
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
		5)  echo -n "Can't resolve proxy" ;;
		6)  echo -n "Can't resolve host" ;;
		7)  echo -n "Can't connect" ;;
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
		61) echo -n "Bad content encoding" ;;
		*)  echo -n "Error $1 returned by curl" ;;
	esac
}


file_Age() {
	local sec=$(($(date +%s) - $(date +%s -r "$1" 2>/dev/null || date +%s)))
	if [ $sec -lt 86400 ]; then
		printf '%02d:%02d' $(($sec/3600)) $(($sec%3600/60))
	elif [ $sec -lt 172800 ]; then
		printf '1 day %02d:%02d' $(($sec%86400/3600)) $(($sec%3600/60))
	else
		printf '%d days %02d:%02d' $(($sec/86400)) $(($sec%86400/3600)) $(($sec%3600/60))
	fi
}


rand() {
	local min="$1" max="$2"
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
		echo "-----------------------------------------------------------"
		printf " %-25s  %30s\n" "$1" "$2"
		echo "-----------------------------------------------------------"
	fi
}


footer() {
	if [ "$option" = "cru" ]; then return; fi
	echo "-----------------------------------------------------------"
	printf " %-25s  %30s\n\n" "Uptime $(file_Age "$file_installtime")" "$(if [ $(ls -1 "$dir_reload" | wc -l) -ge 1 ]; then echo "[i] Failed downloads queued"; fi)"
}


load_Whitelist() {
	if [ $((updatecount % 48)) -ne 0 ]; then return; fi
	local cache= curl_exit= domain= http_code= n=0 temp= url=
	log_Skynet "[i] Update whitelist"
	# Whitelist router, reserved IP addresses and static DNS:
	echo "add Skynet-Temp $(nvram get wan0_ipaddr) comment \"Whitelist: wan0_ipaddr\"
	add Skynet-Temp $(nvram get wan0_gateway) comment \"Whitelist: wan0_gateway\"
	add Skynet-Temp $(nvram get wan0_dns | awk '{print $1}') comment \"Whitelist: wan0_dns\"
	add Skynet-Temp $(nvram get wan0_dns | awk '{print $2}') comment \"Whitelist: wan0_dns\"
	add Skynet-Temp $(nvram get dhcp_dns1_x) comment \"Whitelist: dhcp_dns1_x\"
	add Skynet-Temp $(nvram get dhcp_dns2_x) comment \"Whitelist: dhcp_dns2_x\"
	add Skynet-Temp 0.0.0.0/8 comment \"Whitelist: current network\"
	add Skynet-Temp 10.0.0.0/8 comment \"Whitelist: private network\"
	add Skynet-Temp 127.0.0.0/8 comment \"Whitelist: loopback addresses\"
	add Skynet-Temp 169.254.0.0/16 comment \"Whitelist: link-local addresses\"
	add Skynet-Temp 172.16.0.0/12 comment \"Whitelist: private network\"
	add Skynet-Temp 192.168.0.0/16  comment \"Whitelist: private network\"
	add Skynet-Temp 224.0.0.0/4  comment \"Whitelist: IP multicast\"
	add Skynet-Temp 255.255.255.255/32 comment \"Whitelist: limited broadcast\"
	add Skynet-Temp 8.8.8.8 comment \"Whitelist: Google Public DNS\"
	add Skynet-Temp 8.8.4.4 comment \"Whitelist: Google Public DNS\"
	add Skynet-Temp 1.1.1.1 comment \"Whitelist: Cloudflare DNS\"
	add Skynet-Temp 1.0.0.1 comment \"Whitelist: Cloudflare DNS\"" | tr -d '\t' | filter_IP_Line > "$dir_temp/ipset"
	# Whitelist ip:
	echo "$whitelist_ip" | filter_IP_CIDR | awk '{printf "add Skynet-Temp %s comment \"Whitelist: %s\"\n", $1, $1}' >> "$dir_temp/ipset"
	# Whitelist domain:
	for domain in $(echo "internic.net ipinfo.io $whitelist_domain $(echo "$blacklist_set" | strip_Domain) $(nvram get ntp_server0) $(nvram get ntp_server1)" | filter_Word); do
		domain_Lookup "$domain" | awk -v domain="$domain" '{printf "add Skynet-Temp %s comment \"Whitelist: %s\"\n", $1, domain}' >> "$dir_temp/ipset" &
		n=$((n + 1)); if [ $((n % 50)) -eq 0 ]; then wait; fi
	done
	wait
	# Whitelist root hints:
	url="http://www.internic.net/domain/named.root"
	temp="$dir_temp/named.root"; touch "$temp"
	cache="$dir_cache2/named.root"
	if http_code=$(curl -sf --location --connect-timeout 10 --max-time 180 --limit-rate "$throttle" --user-agent "$useragent" --output "$temp" --write-out "%{http_code}" "$url" --remote-time --time-cond "$cache") && [ "$http_code" = "200" ]; then
		mv -f "$temp" "$cache"
	fi
	if [ -f "$cache" ]; then
		< "$cache" filter_IP_CIDR | filter_PrivateIP | awk '{printf "add Skynet-Temp %s comment \"Whitelist: Root hints\"\n", $1}' >> "$dir_temp/ipset"
	fi
	rm -f "$temp";
	# Update ipset:
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net hashsize "$(($(wc -l < "$dir_temp/ipset") + 8))" comment
	ipset restore -! -f "$dir_temp/ipset"
	ipset swap "Skynet-Whitelist" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
}


load_Blacklist() {
	if [ "$option" = "cru" ]; then return; fi
	log_Skynet "[i] Update blacklist_ip/cidr"
	echo "$blacklist_ip" | filter_IP_CIDR | filter_PrivateIP | awk '{printf "add Skynet-Temp %s comment \"Blacklist: %s\"\n", $1, $1}' > "$dir_temp/ipset"
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net hashsize "$(($(wc -l < "$dir_temp/ipset") + 8))" comment
	ipset restore -! -f "$dir_temp/ipset"
	ipset swap "Skynet-Blacklist" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
}


load_Domain() {
	if [ $((updatecount % 48)) -ne 0 ]; then return; fi
	local domain= n=0
	log_Skynet "[i] Update blacklist_domain"
	true > "$dir_temp/ipset"
	for domain in $(echo "$blacklist_domain" | filter_Word); do
		domain_Lookup "$domain" | filter_PrivateIP | awk -v domain="$domain" '{printf "add Skynet-Temp %s comment \"Blacklist: %s\"\n", $1, domain}' >> "$dir_temp/ipset" &
		n=$((n + 1)); if [ $((n % 50)) -eq 0 ]; then wait; fi
	done
	wait
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net hashsize "$(($(wc -l < "$dir_temp/ipset") + 8))" comment
	ipset restore -! -f "$dir_temp/ipset"
	ipset swap "Skynet-Domain" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
}


load_ASN() {
	if [ $((updatecount % 48)) -ne 0 ] && [ ! -f "$dir_reload/asn" ]; then return; fi
	local asn= n=0
	log_Skynet "[i] Update blacklist_asn"
	rm -f "$dir_reload/asn"
	true > "$dir_temp/ipset"
	for asn in $(echo "$blacklist_asn" | filter_ASN); do
		(	# subshell
			url="https://ipinfo.io/$asn"
			temp="$dir_temp/$asn"
			http_code=$(curl -sf --location --connect-timeout 10 --max-time 180 --limit-rate "$throttle" --user-agent "$useragent" --output "$temp" --write-out "%{http_code}" "$url"); curl_exit=$?
			if [ $curl_exit -eq 0 ]; then
				< "$temp" filter_IP_CIDR | filter_PrivateIP | awk -v asn="$asn" '{printf "add Skynet-Temp %s comment \"Blacklist: %s\"\n", $1, asn}' | awk '!x[$0]++' >> "$dir_temp/ipset"
			else
				log_Skynet "[*] Download error HTTP/$http_code $(curl_Error $curl_exit) $url"
				touch "$dir_reload/asn"
			fi
			rm -f "$temp"
		) &
		n=$((n + 1)); if [ $((n % 10)) -eq 0 ]; then wait; fi
		if [ -f "$dir_reload/asn" ]; then return; fi
	done
	wait
	if [ -f "$dir_reload/asn" ]; then return; fi
	ipset -q destroy "Skynet-Temp"
	ipset create "Skynet-Temp" hash:net hashsize "$(($(wc -l < "$dir_temp/ipset") + 8))" comment
	ipset restore -! -f "$dir_temp/ipset"
	ipset swap "Skynet-ASN" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
}


load_Set() {
	log_Skynet "[i] Update $comment"
	< "$cache" filter_IP_CIDR | filter_PrivateIP | awk -v comment="$comment" '{printf "add Skynet-Temp %s comment \"Blacklist: %s\"\n", $1, comment}' > "$dir_temp/ipset"
	if ! ipset list -n "$setname" >/dev/null 2>&1; then
		ipset create "$setname" hash:net hashsize 64 maxelem 262144 comment
		ipset add Skynet-Master "$setname" comment "$comment"
	fi
	ipset -q destroy "Skynet-Temp"
	ipset create "Skynet-Temp" hash:net hashsize "$(($(wc -l < "$dir_temp/ipset") + 8))" maxelem 262144 comment
	ipset restore -! -f "$dir_temp/ipset"
	ipset swap "$setname" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
	date >> "$dir_update/$comment.log"; log_Tail "$dir_update/$comment.log"
}


download_Set() {
	local cache= comment= curl_exit= dir= http_code= line= list= lookup= setname= temp= update_cycles= url=
	echo "$blacklist_set" | filter_URL_Line > "$dir_temp/blacklist_set"

	while IFS= read -r line; do
		url=$(echo "$line" | filter_URL)
		comment=$(echo "$line" | filter_Comment)
		update_cycles=$(echo "$line" | filter_Update_Cycles)
		setname="Skynet-$(echo -n "$url" | md5sum | cut -c1-24)"

		if [ -z "$comment" ]; then
			comment=$(basename "$url")
		fi
		if [ -z "$update_cycles" ]; then
			update_cycles=4
		fi
		if [ -f "$dir_reload/$setname" ]; then
			update_cycles=1
			rm -f "$dir_reload/$setname"
		fi
		if [ $((updatecount % update_cycles)) -ne 0 ]; then
			continue
		fi

		temp="$dir_temp/$setname"; touch "$temp"
		cache="$dir_cache1/$setname"
		http_code=$(curl -sf --location --connect-timeout 10 --max-time 180 --limit-rate "$throttle" --user-agent "$useragent" --output "$temp" --write-out "%{http_code}" "$url" --remote-time --time-cond "$cache"); curl_exit=$?
		if [ $curl_exit -eq 0 ]; then
			if [ "$http_code" = "304" ] && ! ipset list -n "$setname" >/dev/null 2>&1; then
				load_Set
			elif [ "$http_code" = "304" ]; then
				log_Skynet "[i] Fresh $comment"
			elif [ -f "$cache" ] && cmp -s "$temp" "$cache" && ipset list -n "$setname" >/dev/null 2>&1; then
				log_Skynet "[!] Redownload $comment"
			else
				mv -f "$temp" "$cache"
				load_Set
			fi
		else
			log_Skynet "[*] Download error HTTP/$http_code $(curl_Error $curl_exit) $url"
			touch "$dir_reload/$setname"
		fi
		rm -f "$temp"
	done < "$dir_temp/blacklist_set"

	# Unload unlisted sets
	if [ "$option" = "cru" ]; then return; fi
	lookup=$(ipset list Skynet-Master | filter_Skynet_Set | tr -d '"' | awk '{print $1, $7}')
	for url in $(echo "$blacklist_set" | filter_URL); do
		list="$list Skynet-$(echo -n "$url" | md5sum | cut -c1-24)"
	done
	for setname in $(echo "$lookup" | sort -k2 | awk '{print $1}'); do
		if ! echo "$list" | grep -q "$setname"; then
			log_Skynet "[i] Unload $(echo "$lookup" | awk -v setname="$setname" '$1 == setname {print $2}')"
			ipset -q del "Skynet-Master" "$setname"
			ipset -q destroy "$setname"
		fi
	done

	# Cleanup cache and reload directory
	for dir in "$dir_cache1" "$dir_reload"; do
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
	if [ $i -eq 300 ]; then
		log_Skynet "[*] NTP failed to start after 5 minutes - Please fix immediately!"
		touch "$dir_reload/all"
		echo; exit 1;
	fi
	i=$((i + 1)); sleep 1
done


if [ "$command" = "update" ] || [ "$command" = "reset" ]; then
	for i in 1 2 3 4 5 6; do
		if ping -q -w1 -c1 google.com >/dev/null 2>&1; then break; fi
		if ping -q -w1 -c1 github.com >/dev/null 2>&1; then break; fi
		if ping -q -w1 -c1 amazon.com >/dev/null 2>&1; then break; fi
		if [ $i -eq 1 ]; then log_Skynet "[!] Waiting for internet connectivity..."; fi
		if [ $i -eq 6 ]; then
			log_Skynet "[*] Internet connectivity error"
			touch "$dir_reload/all"
			echo; exit 1
		fi
		sleep 9
	done
fi


if [ "$command" = "update" ] && [ "$option" = "cru" ]; then
	throttle="1M"
	sleep 10
fi


lockfile="/tmp/var/lock/skynet.lock"
exec 99>$lockfile
if ! flock -n 99; then
	echo "[i] Skynet Lite is locked, please try again later"; echo; exit 1
fi


unset i sec


#######################
#- Start Skynet Lite -#
#######################


ip=$(echo "$command" | is_IP) || ip="noip"
case "$command" in
	reset)
		header "Reset"
		log_Skynet "[i] Install"
		rm -f "$dir_reload/"*
		rm -f "$dir_system/"*
		rm -f "$dir_temp/"*
		touch "$file_installtime"
		touch "$file_warninglog"
		touch "$file_errorlog"
		echo "0" > "$file_updatecount"
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
		m1=$((rand + 0));  m2=$((rand + 15))
		m3=$((rand + 30)); m4=$((rand + 45))
		cru d Skynet_update
		cru a Skynet_update "$m1,$m2,$m3,$m4 * * * * nice -n 19 sh /jffs/scripts/firewall update cru"
		unload_IPTables
		unload_LogIPTables
		unload_IPSets
		echo 'create Skynet-Master list:set size 64 comment counters
		create Skynet-Blacklist hash:net hashsize 64 comment
		create Skynet-Domain hash:net hashsize 64 comment
		create Skynet-ASN hash:net hashsize 64 comment
		create Skynet-Whitelist hash:net hashsize 64 comment
		add Skynet-Master Skynet-Blacklist comment "blacklist_ip/cidr"
		add Skynet-Master Skynet-Domain comment "blacklist_domain"
		add Skynet-Master Skynet-ASN comment "blacklist_asn"' | tr -d '\t' | ipset restore -!
		load_IPTables
		load_LogIPTables
		load_Whitelist
		load_Blacklist
		load_Domain
		load_ASN
		download_Set
		footer
	;;


	update)
		header "Update"
		if [ "$option" = "cru" ]; then
			updatecount=$(head -1 "$file_updatecount" 2>/dev/null)
			updatecount=$((updatecount + 1))
			echo "$updatecount" > "$file_updatecount"
		fi
		if [ -f "$dir_reload/all" ]; then
			rm -f "$dir_reload/all"
			updatecount="0"
		fi
		load_Whitelist
		load_Blacklist
		load_Domain
		load_ASN
		download_Set
		footer
	;;


	uninstall)
		header "Uninstall"
		log_Skynet "[*] Uninstall Skynet Lite"
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
		echo
	;;


	warning)
		header
		if [ -f "$file_warninglog" ] && [ $(wc -l < "$file_warninglog") -ge 1 ]; then
			cat "$file_warninglog"
		else
			echo "Empty warning.log"
		fi
		echo
	;;


	error)
		header
		if [ -f "$file_errorlog" ] && [ $(wc -l < "$file_errorlog") -ge 1 ]; then
			cat "$file_errorlog"
		else
			echo "Empty error.log"
		fi
		echo
	;;


	fresh)
		header "Blacklist" "(server) Update time"
		lookup=$(ipset list Skynet-Master | filter_Skynet_Set | tr -d '"' | awk '{print $1, $7}')
		cd "$dir_cache1"
		for setname in $(ls -1t | filter_Skynet_Set); do
			printf " %-40s  %15s\n" "$(echo "$lookup" | awk -v setname="$setname" '$1 == setname {print $2}')" "$(file_Age "$dir_cache1/$setname")"
		done
		footer
	;;


	entries)
		header "Blacklist" "Number of entries"
		table=""
		lookup=$(ipset list Skynet-Master | filter_Skynet | tr -d '"' | awk '{print $1, $7}')
		for setname in $(echo "$lookup" | awk '{print $1}'); do
			table=$(printf "$table\n$(echo "$lookup" | awk -v setname="$setname" '$1 == setname {print $2}') $(ipset list -terse "$setname" | grep -F 'Number of entries' | grep -Eo '[0-9]+')")
		done
		echo "$table" | tail -n +2 | sort -k2gr | awk '{printf " %-40s  %15s\n", $1, $2}'
		footer
	;;


	help)
		header "Commands"
		echo " firewall"
		echo " firewall 1.1.1.1"
		echo " firewall fresh"
		echo " firewall entries"
		echo " firewall warning"
		echo " firewall error"
		echo " firewall update"
		echo " firewall reset"
		echo " firewall uninstall"
		echo " firewall help"
		footer
	;;


	"$ip")
		header "Search for $ip"
		if ipset -q test "Skynet-Whitelist" "$ip"; then
			echo " [*] whitelist"
		else
			echo " [ ] whitelist"
		fi
		lookup=$(ipset list Skynet-Master | filter_Skynet | tr -d '"' | awk '{print $1, $7}')
		for setname in $(echo "$lookup" | sort -k2 | awk '{print $1}'); do
			if ipset -q test "$setname" "$ip"; then
				echo " [*] $(echo "$lookup" | awk -v setname="$setname" '$1 == setname {print $2}')"
			else
				echo " [ ] $(echo "$lookup" | awk -v setname="$setname" '$1 == setname {print $2}')"
			fi
		done
		footer
	;;


	*)
		header "Blacklist" "Packets blocked"
		ipset list Skynet-Master | filter_Skynet | tr -d '"' | sort -k3,3gr -k7,7 | awk '{printf " %-40s  %15s\n", $7, $3}'
		footer
	;;
esac


log_Tail "$file_warninglog"
log_Tail "$file_errorlog"
rm -f "$dir_temp/"*
