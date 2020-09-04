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
# blocklist_ip, blocklist_domain, blocklist_asn and passlist_ip can optional use one <comment> tag per list.
#


###################
#- Configuration -#
###################


filtertraffic="all"		# inbound | outbound | all
logmode="enabled"		# enabled | disabled
loginvalid="disabled"	# enabled | disabled
debugupdate="enabled"	# enabled | disabled


blocklist_set="		<binarydefense>		https://www.binarydefense.com/banlist.txt  {4}
					<blocklist.de>		https://iplists.firehol.org/files/blocklist_de.ipset  {1}
					<ciarmy>			https://cinsscore.com/list/ci-badguys.txt  {1}
					<cleantalk>			https://iplists.firehol.org/files/cleantalk_7d.ipset  {1}
					<dshield>			https://iplists.firehol.org/files/dshield_7d.netset  {1}
					<greensnow>			https://iplists.firehol.org/files/greensnow.ipset  {1}
					<maxmind>			https://www.maxmind.com/en/high-risk-ip-sample-list  {48}
					<myip>				https://www.myip.ms/files/blacklist/csf/latest_blacklist.txt  {4}
					<snort>				https://labs.snort.org/feeds/ip-filter.blf  {12}
					<spamhaus_drop>		https://www.spamhaus.org/drop/drop.txt  {12}
					<spamhaus_edrop>	https://www.spamhaus.org/drop/edrop.txt  {12}
					<tor_exits>			https://iplists.firehol.org/files/tor_exits.ipset  {1}"
blocklist_ip=""
blocklist_domain=""
blocklist_asn=""
passlist_ip=""
passlist_domain=""


##########################
#- End of configuration -#
##########################


command="$1"
option="$2"
throttle=0
updatecount=0
iotblocked="disabled"
version="3.1.8"
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


###############
#- Functions -#
###############


unload_IPTables() {
	iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Primary src -j DROP 2>/dev/null
	iptables -t raw -D PREROUTING -i br0 -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Primary dst -j DROP 2>/dev/null
	iptables -t raw -D OUTPUT -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Primary dst -j DROP 2>/dev/null
	iptables -D SSHBFP -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j SET --add-set Skynet-Blocklist src 2>/dev/null
	iptables -D SSHBFP -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	ip6tables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -D logdrop -m state --state NEW -m limit --limit 4/sec -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	ip6tables -D logdrop -m state --state NEW -m limit --limit 4/sec -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
}


load_IPTables() {
	local pos1=
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
		iptables -t raw -I PREROUTING -i "$iface" -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Primary src -j DROP 2>/dev/null
	fi
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
		iptables -t raw -I PREROUTING -i br0 -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Primary dst -j DROP 2>/dev/null
		iptables -t raw -I OUTPUT -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Primary dst -j DROP 2>/dev/null
	fi
	if [ "$(nvram get sshd_enable)" = "1" ] && [ "$(nvram get sshd_bfp)" = "1" ] && [ "$(uname -o)" = "ASUSWRT-Merlin" ] && [ "$(nvram get switch_wantag)" != "movistar" ]; then
		pos1="$(iptables --line -nL SSHBFP | grep -F "seconds: 60 hit_count: 4" | grep -E 'DROP|logdrop' | awk '{print $1}')"
		iptables -I SSHBFP "$pos1" -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j SET --add-set Skynet-Blocklist src 2>/dev/null
		iptables -I SSHBFP "$pos1" -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	fi
}


unload_LogIPTables() {
	iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Primary src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -t raw -D PREROUTING -i br0 -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Primary dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -t raw -D OUTPUT -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Primary dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -D logdrop -m state --state NEW -j LOG --log-prefix "[BLOCKED - INVALID] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -D FORWARD -i br0 -m set --match-set Skynet-IOT src ! -o tun2+ -j LOG --log-prefix "[BLOCKED - IOT] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
}


load_LogIPTables() {
	local pos2= pos3= pos4= pos5=
	if [ "$logmode" = "enabled" ]; then
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
			pos2="$(iptables --line -nL PREROUTING -t raw | grep -F "Skynet-Primary src" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos2" -i "$iface" -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Primary src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
			pos3="$(iptables --line -nL PREROUTING -t raw | grep -F "Skynet-Primary dst" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos3" -i br0 -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Primary dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
			pos4="$(iptables --line -nL OUTPUT -t raw | grep -F "Skynet-Primary dst" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I OUTPUT "$pos4" -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Primary dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
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
	ipset -q destroy Skynet-Primary
	ipset -n list | filter_Skynet | xargs -I setname ipset -q destroy setname
}


lookup_Domain() {
	set -o pipefail; nslookup "$1" 2>/dev/null | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | awk 'NR > 2'
	if [ $? -ne 0 ]; then log_Skynet "[*] Can't resolve $1"; fi
}


strip_Domain() {
	grep -Eo 'https?://\S+' | cut -d'/' -f3
}


filter_Domain() {
	awk '{gsub("<.+>", ""); print}' | grep -Eo '(([a-z](-?[a-z0-9])*)\.)+[a-z]{2,}'
}


is_Domain() {
	grep -Eo '^(([a-z](-?[a-z0-9])*)\.)+[a-z]{2,}$'
}


filter_URL() {
	grep -Eo 'https?://\S+'
}


filter_URL_Line() {
	grep -E 'https?://\S+'
}


filter_IP_CIDR() {
	grep -Eo '(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3}(\/(3[0-2]|[1-2][0-9]|[0-9]))?'
}


filter_Out_PrivateIP() {
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
	grep -Eo '<.+>' | tr -d '<>' | tr ',/"' ";_'" | awk '{$1 = $1; print}' | grep -E '.+'
}


filter_Update_Cycles() {
	grep -Eo '\{[1-9][0-9]*\}' | tr -d '{}' | grep -E '.+'
}


filter_Skynet() {
	grep -E '^Skynet-'
}


filter_Skynet_Set() {
	grep -E '^Skynet-[0-9a-f]{24}'
}


download_Error() {
	if [ "$1" != "22" ]; then
		printf "[*] Download error cURL (%s) " "$1"
		case "$1" in
			 1) printf "Unsupported protocol" ;;
			 2) printf "Failed initialization" ;;
			 3) printf "URL malformat" ;;
			 4) printf "Not built in" ;;
			 5) printf "Can't resolve proxy" ;;
			 6) printf "Can't resolve host" ;;
			 7) printf "Can't connect" ;;
			 8) printf "Weird server reply" ;;
			 9) printf "Remote access denied" ;;
			18) printf "Partial file" ;;
			23) printf "Write error" ;;
			26) printf "Read error" ;;
			27) printf "Out of memory" ;;
			28) case "$2" in
					000) printf "Connection timeout" ;;
					  *) printf "Operation timeout" ;;
				esac ;;
			33) printf "Range error" ;;
			35) printf "SSL connect error" ;;
			36) printf "Bad download resume" ;;
			47) printf "Too many redirects" ;;
			52) printf "Empty reply from server" ;;
			55) printf "Send error" ;;
			56) printf "Receive error" ;;
			60) printf "Peer failed verification" ;;
			61) printf "Bad content encoding" ;;
			 *) printf "Error returned by cURL" ;;
		esac
	else # cURL (22) HTTP error code >= 400
		printf "[*] Download error HTTP/%s " "$2"
		case "$2" in
			400) printf "Bad request" ;;
			401) printf "Unauthorized" ;;
			402) printf "Payment required" ;;
			403) printf "Forbidden" ;;
			404) printf "Not found" ;;
			405) printf "Method not allowed" ;;
			406) printf "Not acceptable" ;;
			407) printf "Proxy authentication required" ;;
			408) printf "Request timeout" ;;
			409) printf "Conflict" ;;
			410) printf "Gone" ;;
			411) printf "Length required" ;;
			412) printf "Precondition failed" ;;
			413) printf "Payload too large" ;;
			414) printf "URI too long" ;;
			415) printf "Unsupported media type" ;;
			416) printf "Range not satisfiable" ;;
			417) printf "Expectation failed" ;;
			425) printf "Too early" ;;
			426) printf "Upgrade required" ;;
			428) printf "Precondition required" ;;
			429) printf "Too many requests" ;;
			431) printf "Request header fields too large" ;;
			451) printf "Unavailable for legal reasons" ;;
			500) printf "Internal server error" ;;
			501) printf "Not implemented" ;;
			502) printf "Bad gateway" ;;
			503) printf "Service unavailable" ;;
			504) printf "Gateway timeout" ;;
			505) printf "HTTP version not supported" ;;
			506) printf "Variant also negotiates" ;;
			510) printf "Not extended" ;;
			511) printf "Network authentication required" ;;
	4[0-9][0-9]) printf "Client error" ;;
	5[0-9][0-9]) printf "Server error" ;;
			  *) printf "Unknown error" ;;
		esac
	fi
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
		tail -675 "$1" > "$dir_temp/log" && mv -f "$dir_temp/log" "$1"
	fi
}


lookup_Comment_Init() {
 	echo "Skynet-Passlist,$(echo "$passlist_ip" | filter_Comment || echo "passlist")" > "$dir_temp/lookup.csv"
 	echo "Skynet-Blocklist,$(echo "$blocklist_ip" | filter_Comment || echo "blocklist_ip")" >> "$dir_temp/lookup.csv"
	echo "Skynet-Domain,$(echo "$blocklist_domain" | filter_Comment || echo "blocklist_domain")" >> "$dir_temp/lookup.csv"
	echo "Skynet-ASN,$(echo "$blocklist_asn" | filter_Comment || echo "blocklist_asn")" >> "$dir_temp/lookup.csv"
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


hash_Set() {
	local data="$version $1" file="$dir_system/$2.md5"
	echo -n "$data" | md5sum | cut -c1-32 > "$file"
}


hash_Unmodified() {
	local data="$version $1" file="$dir_system/$2.md5"
	[ "$(echo -n "$data" | md5sum | cut -c1-32)" = "$(head -1 "$file" 2>/dev/null)" ]
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
	printf '\033[?7l' # disable line wrap
	clear; sed -n '2,7s/#//p' "$0"
	echo " Skynet Lite $version by Willem Bartels"
	echo " Code is based on Skynet By Adamm"
	echo
	if [ -n "$1" ]; then
		printf '%s\n' '-----------------------------------------------------------'
		if [ -n "$2" ]; then
			printf ' %-25s  %30s\n' "$1" "$2"
		elif [ $(echo -n "$1" | wc -m) -gt 57 ]; then
			printf ' %.54s...\n' "$1"
		else
			printf ' %s\n' "$1"
		fi
		printf '%s\n' '-----------------------------------------------------------'
	fi
}


footer() {
	if [ "$option" = "cru" ]; then return; fi
	if [ "$1" != "empty" ]; then
		printf '%s\n' '-----------------------------------------------------------'
		printf ' %-25s  %30s\n' \
			"Uptime $(formatted_File_Age "$dir_system/installtime")" \
			"$(if [ $(ls -1 "$dir_reload" | wc -l) -ge 1 ]; then echo "[i] Failed download queued"
			elif [ $(ls -1 "$dir_sleep" | wc -l) -ge 1 ]; then echo "[i] Download sleep"; fi)"
	fi
	printf '\033[?7h\n' # enable line wrap
}


load_Passlist() {
	local passlist_router="add Skynet-Temp $(nvram get wan0_ipaddr) comment \"Passlist: wan0_ipaddr\"
		add Skynet-Temp $(nvram get wan0_realip_ip) comment \"Passlist: wan0_realip_ip\"
		add Skynet-Temp $(nvram get wan0_gateway) comment \"Passlist: wan0_gateway\"
		add Skynet-Temp $(nvram get wan0_xgateway) comment \"Passlist: wan0_xgateway\"
		add Skynet-Temp $(nvram get wan0_dns | awk '{print $1}') comment \"Passlist: wan0_dns\"
		add Skynet-Temp $(nvram get wan0_dns | awk '{print $2}') comment \"Passlist: wan0_dns\"
		add Skynet-Temp $(nvram get dhcp_dns1_x) comment \"Passlist: dhcp_dns1_x\"
		add Skynet-Temp $(nvram get dhcp_dns2_x) comment \"Passlist: dhcp_dns2_x\"
		add Skynet-Temp 0.0.0.0/8 comment \"Passlist: This network\"
		add Skynet-Temp 10.0.0.0/8 comment \"Passlist: Private network\"
		add Skynet-Temp 100.64.0.0/10 comment \"Passlist: Carrier-grade NAT\"
		add Skynet-Temp 127.0.0.0/8 comment \"Passlist: Loopback\"
		add Skynet-Temp 169.254.0.0/16 comment \"Passlist: Link local\"
		add Skynet-Temp 172.16.0.0/12 comment \"Passlist: Private network\"
		add Skynet-Temp 192.0.0.0/24 comment \"Passlist: IETF protocol assignments\"
		add Skynet-Temp 192.0.2.0/24 comment \"Passlist: TEST-NET-1\"
		add Skynet-Temp 192.168.0.0/16 comment \"Passlist: Private network\"
		add Skynet-Temp 198.18.0.0/15 comment \"Passlist: Network interconnect device benchmark testing\"
		add Skynet-Temp 198.51.100.0/24 comment \"Passlist: TEST-NET-2\"
		add Skynet-Temp 203.0.113.0/24 comment \"Passlist: TEST-NET-3\"
		add Skynet-Temp 224.0.0.0/3 comment \"Passlist: Multicast/reserved/limited broadcast\""
	local passlist_domain="$passlist_domain $(echo "$blocklist_set $(nvram get firmware_server)" | strip_Domain)
		$(nvram get ntp_server0) $(nvram get ntp_server1)
		internic.net
		ipinfo.io
		raw.githubusercontent.com
		dns.adguard.com
		dns.cloudflare.com
		dns.google
		dns.opendns.com
		dns.quad9.net
		one.one.one.one
		recpubns1.nstld.net
		recpubns2.nstld.net"

	if [ $((updatecount % 48)) -ne 0 ] && hash_Unmodified "$passlist_router $passlist_ip $passlist_domain" "passlist"; then return; fi
	log_Skynet "[i] Update $(lookup_Comment 'Skynet-Passlist')"
	local cache= curl_exit= domain= http_code= n=0 temp= url=
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net comment
	# Passlist router and reserved IP addresses:
	echo "$passlist_router" | tr -d '\t' | filter_IP_Line | ipset restore -!
	# Passlist ip:
	echo "$passlist_ip" | filter_IP_CIDR | filter_Out_PrivateIP | awk '{printf "add Skynet-Temp %s comment \"Passlist: %s\"\n", $1, $1}' | ipset restore -!
	# Passlist domain:
	for domain in $(echo "$passlist_domain" | filter_Domain | awk '!x[$0]++'); do
		lookup_Domain "$domain" | filter_Out_PrivateIP | awk -v domain="$domain" '{printf "add Skynet-Temp %s comment \"Passlist: %s\"\n", $1, domain}' | ipset restore -! &
		n=$((n + 1)); if [ $((n % 50)) -eq 0 ]; then wait; fi
	done
	wait
	# Passlist root hints:
	url="http://www.internic.net/domain/named.root"
	temp="$dir_temp/named.root"; touch "$temp"
	cache="$dir_cache/named.root"

	http_code=$(curl -sf --location --user-agent "$useragent" \
		--connect-timeout 10 --max-time 90 --limit-rate "$throttle" \
		--write-out "%{http_code}" --output "$temp" "$url" \
		--remote-time --time-cond "$cache"); curl_exit=$?

	if [ $curl_exit -eq 0 ] && [ "$http_code" = "200" ]; then
		mv -f "$temp" "$cache"
	fi
	if [ -f "$cache" ]; then
		filter_IP_CIDR < "$cache" | filter_Out_PrivateIP | awk '{printf "add Skynet-Temp %s comment \"Passlist: Root hints\"\n", $1}' | ipset restore -!
	fi
	rm -f "$temp";
	ipset swap "Skynet-Passlist" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
	hash_Set "$passlist_router $passlist_ip $passlist_domain" "passlist"
}


load_Blocklist() {
	if hash_Unmodified "$blocklist_ip" "blocklist_ip"; then return; fi
	log_Skynet "[i] Update $(lookup_Comment 'Skynet-Blocklist')"
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net comment
	echo "$blocklist_ip" | filter_IP_CIDR | filter_Out_PrivateIP | awk '{printf "add Skynet-Temp %s comment \"Blocklist: %s\"\n", $1, $1}' | ipset restore -!
	ipset swap "Skynet-Blocklist" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
	hash_Set "$blocklist_ip" "blocklist_ip"
}


load_Domain() {
	if [ $((updatecount % 48)) -ne 0 ] && hash_Unmodified "$blocklist_domain" "blocklist_domain"; then return; fi
	log_Skynet "[i] Update $(lookup_Comment 'Skynet-Domain')"
	local domain= n=0
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net comment
	for domain in $(echo "$blocklist_domain" | filter_Domain); do
		lookup_Domain "$domain" | filter_Out_PrivateIP | awk -v domain="$domain" '{printf "add Skynet-Temp %s comment \"Blocklist: %s\"\n", $1, domain}' | ipset restore -! &
		n=$((n + 1)); if [ $((n % 50)) -eq 0 ]; then wait; fi
	done
	wait
	ipset swap "Skynet-Domain" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
	hash_Set "$blocklist_domain" "blocklist_domain"
}


load_ASN() {
	if [ $((updatecount % 48)) -ne 0 ] && [ ! -f "$dir_reload/asn" ] && hash_Unmodified "$blocklist_asn" "blocklist_asn"; then return; fi
	log_Skynet "[i] Update $(lookup_Comment 'Skynet-ASN')"
	local asn= n=0
	rm -f "$dir_reload/asn"
	ipset -q destroy "Skynet-Temp"
	ipset create "Skynet-Temp" hash:net comment
	for asn in $(echo "$blocklist_asn" | filter_ASN); do
		(
			url="https://ipinfo.io/$asn"
			temp="$dir_temp/$asn"

			http_code=$(curl -sf --location --user-agent "$useragent" \
				--connect-timeout 10 --max-time 90 --limit-rate "$throttle" \
				--write-out "%{http_code}" --output "$temp" "$url"); curl_exit=$?

			if [ $curl_exit -eq 0 ]; then
				filter_IP_CIDR < "$temp" | filter_Out_PrivateIP | awk '!x[$0]++' | awk -v asn="$asn" '{printf "add Skynet-Temp %s comment \"Blocklist: %s\"\n", $1, asn}' | ipset restore -!
			elif [ "$http_code" = "429" ]; then
				log_Skynet "$(download_Error $curl_exit $http_code) $url"
				touch "$dir_temp/asn_too_many_requests"
				rm -f "$dir_reload/asn"
			else
				log_Skynet "$(download_Error $curl_exit $http_code) $url"
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
	hash_Set "$blocklist_asn" "blocklist_asn"
}


load_Set() {
	log_Skynet "[i] Update $comment"
	if ! ipset -n list "$setname" >/dev/null 2>&1; then
		ipset create "$setname" hash:net maxelem 524288 comment
		ipset add Skynet-Primary "$setname" comment "$comment"
	fi
	grep -E '^[+][0-9]' < "$dir_temp/diff" | cut -c2- > "$dir_temp/add"
	grep -E '^[-][0-9]' < "$dir_temp/diff" | cut -c2- > "$dir_temp/del"
	awk -v setname="$setname" -v comment="$comment" '{printf "add %s %s comment \"Blocklist: %s\"\n", setname, $1, comment}' "$dir_temp/add" | ipset restore -!
	awk -v setname="$setname" '{printf "del %s %s\n", setname, $1}' "$dir_temp/del" | ipset restore -!
	if [ "$debugupdate" = "enabled" ]; then
		printf '%s | %6s | %7s | %7s |\n' \
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
	echo " [i] Compare $comment"
	if cmp -s "$cache" "$temp"; then
		printf '\033[1A\033[K' # cursor up and clear
		return 0
	fi
	if [ ! -f "$filtered_cache" ]; then
		touch "$filtered_cache"
	fi
	{
		case "$url" in
			*.zip)			unzip -p "$temp";;
			*.tgz|*.tar.gz)	tar -xzOf "$temp";;
			*)				gunzip -c "$temp" 2>/dev/null || cat "$temp";;
		esac
	} | filter_IP_CIDR | filter_Out_PrivateIP | sort -u > "$filtered_temp"
	diff "$filtered_cache" "$filtered_temp" > "$dir_temp/diff"; local diff_exit=$?
	printf '\033[1A\033[K' # cursor up and clear
	return $diff_exit
}


download_Set() {
	local cache= comment= curl_exit= dir= filtered_cache= filtered_temp= http_code= line= list= lookup= setname= temp= update_cycles= url=
	echo "$blocklist_set" | filter_URL_Line > "$dir_temp/blocklist_set"

	while IFS= read -r line; do
		url=$(echo "$line" | filter_URL)
		comment=$(echo "$line" | filter_Comment || echo "<$(basename "$url")>" | filter_Comment)
		update_cycles=$(echo "$line" | filter_Update_Cycles || echo 4)
		setname="Skynet-$(echo -n "$url" | md5sum | cut -c1-24)"
		echo "$setname,$comment" >> "$dir_temp/lookup.csv"

		if [ $((updatecount % update_cycles)) -ne 0 ] && [ ! -f "$dir_reload/$setname" ]; then
			continue
		fi
		if [ -f "$dir_sleep/$setname" ] && [ $(file_Age "$dir_sleep/$setname") -lt 14400 ]; then
			log_Skynet "[!] Sleep $(formatted_Time $((14400 - $(file_Age "$dir_sleep/$setname")))) $comment"
			continue
		fi
		rm -f "$dir_reload/$setname"
		rm -f "$dir_sleep/$setname"

		echo " [i] Download $comment"
		temp="$dir_temp/${setname}_unfiltered"; touch "$temp"
		cache="$dir_cache/$setname"
		filtered_temp="$dir_temp/${setname}_filtered"
		filtered_cache="$dir_filtered/$setname"

		http_code=$(curl -sf --location --user-agent "$useragent" \
			--connect-timeout 10 --max-time 90 --limit-rate "$throttle" \
			--write-out "%{http_code}" --output "$temp" "$url" \
			--remote-time --time-cond "$cache" \
			--header "Accept-encoding: gzip"); curl_exit=$?
		printf '\033[1A\033[K' # cursor up and clear

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
			log_Skynet "$(download_Error $curl_exit $http_code) $url"
			touch "$dir_sleep/$setname"
		else
			log_Skynet "$(download_Error $curl_exit $http_code) $url"
			touch "$dir_reload/$setname"
		fi
		rm -f "$temp" "$filtered_temp"
	done < "$dir_temp/blocklist_set"
	sort -t, -k2 < "$dir_temp/lookup.csv" > "$dir_system/lookup.csv"

	if hash_Unmodified "$blocklist_set" "blocklist_set"; then return; fi
	# Unload unlisted sets
	list=$(filter_Skynet_Set < "$dir_system/lookup.csv" | awk -F, '{print $1}')
	for setname in $(ipset list Skynet-Primary | filter_Skynet_Set | awk '{print $1}'); do
		if ! echo "$list" | grep -q "$setname"; then
			ipset -q del "Skynet-Primary" "$setname"
			ipset -q destroy "$setname"
		fi
	done
	# Cleanup directories
	for dir in "$dir_cache" "$dir_filtered" "$dir_reload" "$dir_sleep" "$dir_update"; do
		cd "$dir"
		for setname in $(ls -1 | filter_Skynet_Set); do
			if ! echo "$list" | grep -q "$setname"; then
				rm -f "$dir/$setname"
			fi
		done
	done
	# Cleanup debug directory
	list=$(filter_Skynet_Set < "$dir_system/lookup.csv" | awk -F, '{print $2 ".log"}')
	cd "$dir_debug"
	for comment in $(ls -1); do
		if ! echo "$list" | grep -q "$comment"; then
			rm -f "$dir_debug/$comment"
		fi
	done
	hash_Set "$blocklist_set" "blocklist_set"
}


############################
#- Initialize Skynet Lite -#
############################

domain=$(echo "$command" | is_Domain) && command="domain"
ip=$(echo "$command" | is_IP) && command="ip"
if ! ipset list -n Skynet-Primary >/dev/null 2>&1; then
	command="reset"
	option=""
fi


if [ "$(nvram get wan0_proto)" = "pppoe" ]; then
	iface="ppp0"
else
	iface="$(nvram get wan0_ifname)"
fi


i=0
while [ "$(nvram get ntp_ready)" != "1" ] && [ "$command" != "uninstall" ]; do
	if [ $i -eq 0 ]; then log_Skynet "[i] Waiting for NTP to sync..."; fi
	if [ $i -eq 300 ]; then log_Skynet "[*] NTP failed to start after 5 minutes - Please fix immediately!"; echo; exit 1; fi
	i=$((i + 1)); sleep 1
done
start_time=$(($(date +%s) - i))


if [ "$command" = "update" ] || [ "$command" = "reset" ]; then
	for i in 1 2 3 4 5 6; do
		if ping -q -w1 -c1 dns.google >/dev/null 2>&1; then break; fi
		if ping -q -w1 -c1 one.one.one.one >/dev/null 2>&1; then break; fi
		if ping -q -w1 -c1 dns.opendns.com >/dev/null 2>&1; then break; fi
		if [ $i -eq 1 ]; then log_Skynet "[!] Waiting for internet connectivity..."; fi
		if [ $i -eq 6 ]; then log_Skynet "[*] Internet connectivity error"; echo; exit 1; fi
		sleep 9
	done
fi


if [ "$command" = "update" ] && [ "$option" = "cru" ]; then
	throttle="2M"
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
		cru a Skynet_update "$((rand + 0)),$((rand + 15)),$((rand + 30)),$((rand + 45)) * * * * nice -n 19 sh /jffs/scripts/firewall update cru"
		unload_IPTables
		unload_LogIPTables
		unload_IPSets
		echo 'create Skynet-Primary list:set size 64 comment counters
			create Skynet-Blocklist hash:net comment
			create Skynet-Domain hash:net comment
			create Skynet-ASN hash:net comment
			create Skynet-Passlist hash:net comment
			add Skynet-Primary Skynet-Blocklist comment "blocklist_ip"
			add Skynet-Primary Skynet-Domain comment "blocklist_domain"
			add Skynet-Primary Skynet-ASN comment "blocklist_asn"' | tr -d '\t' | ipset restore -!
		load_IPTables
		load_LogIPTables
		load_Passlist
		load_Blocklist
		load_Domain
		load_ASN
		download_Set
		footer
	;;


	update)
		header "Update"
		lookup_Comment_Init
		load_Passlist
		load_Blocklist
		load_Domain
		load_ASN
		download_Set
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
		echo " [i] Skynet Lite has been successfully uninstalled"
		footer "empty"; exit 0
	;;


	domain)
		lookup_Domain "$domain" > "$dir_temp/ip.txt" 2>&1
		header "Search for $(tr '\n' ' ' < $dir_temp/ip.txt)"
		while IFS=, read -r setname comment; do
			ip_found="false"
			while IFS=, read -r ip; do
				if ipset -q test "$setname" "$ip"; then
					echo " [*] $comment"
					ip_found="true"; break
				fi
			done < "$dir_temp/ip.txt"
			if [ "$ip_found" = "false" ]; then
				echo " [ ] $comment"
			fi
		done < "$dir_system/lookup.csv"
		footer
	;;


	ip)
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
			echo " [i] Empty warning.log"
		fi
		footer "empty"
	;;


	error)
		header
		if [ -f "$dir_skynet/error.log" ] && [ $(wc -l < "$dir_skynet/error.log") -ge 1 ]; then
			cat "$dir_skynet/error.log"
		else
			echo " [i] Empty error.log"
		fi
		footer "empty"
	;;


	fresh)
		header "Blocklist" "Client file age"
		true > "$dir_temp/file.csv"
		filter_Skynet_Set < "$dir_system/lookup.csv" | while IFS=, read -r setname comment; do
			age=$(file_Age "$dir_update/$setname")
			echo "$comment,$(formatted_Time "$age"),$age" >> "$dir_temp/file.csv"
		done
		sort -t, -k3n < "$dir_temp/file.csv" | awk -F, '{printf " %-40s  %15s\n", $1, $2}'
		footer
	;;


	frequency)
		header "Blocklist" "Average update time"
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
		echo " firewall 8.8.8.8"
		echo " firewall dns.google"
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
		header "Blocklist" "Packets blocked"
		true > "$dir_temp/file.csv"
		ipset list Skynet-Primary | filter_Skynet | awk '{print $1 "," $3}' | while IFS=, read -r setname blocked; do
			echo "$(lookup_Comment "$setname"),$blocked" >> "$dir_temp/file.csv"
		done
		sort -t, -k2nr -k1,1 < "$dir_temp/file.csv" | awk -F, '{printf " %-40s  %15s\n", $1, $2}'
		footer
	;;
esac


rm -f "$dir_temp/"*
log_Tail "$dir_skynet/warning.log"
log_Tail "$dir_skynet/error.log"
