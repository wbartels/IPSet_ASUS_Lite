#!/bin/sh
#  ___ _                 _     _    _ _
# / __| |___  _ _ _  ___| |_  | |  (_) |_ ___
# \__ \ / / || | ' \/ -_)  _| | |__| |  _/ -_)
# |___/_\_\\_, |_||_\___|\__| |____|_|\__\___|
#          |__/
#
#   Skynet Lite by Willem Bartels
#   IP Blocking for ASUS Routers Using IPSet
#   https://github.com/wbartels/IPSet_ASUS_Lite
#
#   Code is based on Skynet by Adamm
#   Advanced IP Blocking for ASUS Routers using IPSet
#   https://github.com/Adamm00/IPSet_ASUS
#   This script will always be open source and free to use
#
#
# Installation:
# curl https://raw.githubusercontent.com/wbartels/IPSet_ASUS_Lite/master/firewall.sh --output /jffs/scripts/firewall && chmod 755 /jffs/scripts/firewall && /jffs/scripts/firewall
#
# Commands:
# firewall help
#
# Readme:
# The cron job is started every 15 minutes.
# By default, the set update process is started after 4 cycles = 1 hour.
# This value can be overridden per set with the {n} tag.
# If supported only changed files will be downloaded, see URL's below for more info.
# This way the update frequencies can be relative high without overloading the servers.
#
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Modified-Since
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-None-Match
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/304
#
# If a download fails, this set will be retried at an interval of 15 minutes.
# Over time, the interval will be extended to a maximum of 6 hours.
#
# Both the <comment> and {n} tags are optional.
# The order of the URL and tags are not important, but must be on the same line.
#
# The other lists (ip and domain) can contain multiple items per list.
# The items on these lists must be separated with a space, tab or newline.
# blocklist_ip, blocklist_domain and passlist_ip can optionally use one <comment> tag per list.
#
# feb 2022: Torproject tor-exits aren't updated for months.
# Thanks https://github.com/SecOps-Institute for creating a tor-exit-nodes list.
#


###################
#- Configuration -#
###################


filtertraffic="all"		# inbound | outbound | all
logmode="enabled"		# enabled | disabled
loginvalid="disabled"	# enabled | disabled

blocklist_set="		<binarydefense>			https://www.binarydefense.com/banlist.txt  {2}
					<blocklist.de>			https://lists.blocklist.de/lists/all.txt  {2}
					<ciarmy>				https://cinsscore.com/list/ci-badguys.txt  {2}
					<cleantalk>				https://iplists.firehol.org/files/cleantalk_7d.ipset  {2}
					<dshield>				https://iplists.firehol.org/files/dshield_7d.netset  {2}
					<greensnow>				https://blocklist.greensnow.co/greensnow.txt  {2}
					<myip>					https://www.myip.ms/files/blacklist/csf/latest_blacklist.txt  {4}
					<spamhaus_drop>			https://www.spamhaus.org/drop/drop.txt  {12}
					<spamhaus_edrop>		https://www.spamhaus.org/drop/edrop.txt  {12}
					<tor_exits>				https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst  {2}"
blocklist_ip=""
blocklist_domain=""

passlist_ip=""
passlist_domain="	dns.adguard.com
					dns.cloudflare.com
					dns.google
					dns.nextdns.io
					dns.opendns.com
					dns.quad9.net
					one.one.one.one"


###############
#- Functions -#
###############


unload_IPTables() {
	iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Primary src -j DROP 2>/dev/null
	iptables -t raw -D PREROUTING -i br0 -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Primary dst -j DROP 2>/dev/null
	iptables -t raw -D OUTPUT -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Primary dst -j DROP 2>/dev/null
	iptables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	ip6tables -D logdrop -m state --state NEW -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -D logdrop -m state --state NEW -m limit --limit 4/sec -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	ip6tables -D logdrop -m state --state NEW -m limit --limit 4/sec -j LOG --log-prefix "DROP " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
}


load_IPTables() {
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
		iptables -t raw -I PREROUTING -i "$iface" -m set ! --match-set Skynet-Passlist src -m set --match-set Skynet-Primary src -j DROP 2>/dev/null
	fi
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
		iptables -t raw -I PREROUTING -i br0 -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Primary dst -j DROP 2>/dev/null
		iptables -t raw -I OUTPUT -m set ! --match-set Skynet-Passlist dst -m set --match-set Skynet-Primary dst -j DROP 2>/dev/null
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
	awk '{gsub("<.+>", ""); print}' | grep -Eo '(([a-z][a-z0-9-]*)\.)+[a-z]{2,62}'
}


is_Domain() {
	grep -Eo '^(([a-z][a-z0-9-]*)\.)+[a-z]{2,62}$'
}


filter_URL() {
	grep -Eo 'https?://\S+'
}


filter_URL_Line() {
	grep -E 'https?://\S+'
}


filter_IP_CIDR() {
	grep -Eo '(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3}(/(3[0-2]|[1-2][0-9]|[0-9]))?'
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
	if [ "$1" = "22" ]; then # HTTP error code >= 400
		printf "[*] Download error HTTP/%s " "$2"
		case "$2" in
			4[0-9][0-9]) printf "Client error" ;;
			5[0-9][0-9]) printf "Server error" ;;
					  *) printf "Unknown error" ;;
		esac
	else
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
}


lookup_Comment() {
	awk -F, -v setname="$1" '$1 == setname {print $2}' "$dir_temp/lookup.csv"
}


formatted_Number() {
	echo -n $1 | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta'
}


formatted_Time() {
	if ! [ "$1" -ge 0 ] 2>/dev/null; then
		printf 'undefined'
	elif [ $1 -lt 86400 ]; then
		printf '%02d:%02d' $(($1/3600)) $(($1%3600/60))
	elif [ $1 -lt 172800 ]; then
		printf '1 day %02d:%02d' $(($1%86400/3600)) $(($1%3600/60))
	else
		printf '%d days %02d:%02d' $(($1/86400)) $(($1%86400/3600)) $(($1%3600/60))
	fi
}


formatted_File_Age() {
	if [ -r "$1" ]; then
		formatted_Time $(($(date +%s) - $(date +%s -r "$1")))
	fi
}


file_Age() {
	if [ -r "$1" ]; then
		echo -n $(($(date +%s) - $(date +%s -r "$1")))
	fi
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
	echo -n $((n + 1)) | tee "$1"
}


# rand() {
#	local min=$1 max=$2
#	echo -n $((min + $(printf '%d' 0x$(openssl rand -hex 2)) * (max - min + 1) / 65025))
# }


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
			"$(if [ $(ls -1 "$dir_reload" | wc -l) -ge 1 ]; then echo "[i] Failed download queued"; fi)"
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
	local passlist_domain="$passlist_domain
		$(echo "$blocklist_set $(nvram get firmware_server) $(nvram get ntp_server0) $(nvram get ntp_server1)" | strip_Domain)
		fastly.com
		github.com
		ibm.com
		raw.githubusercontent.com
		www.internic.net"

	if [ $((updatecount % 96)) -ne 0 ] && hash_Unmodified "$passlist_router $passlist_ip $passlist_domain" "passlist"; then return; fi
	log_Skynet "[i] Update $(lookup_Comment 'Skynet-Passlist')"
	local cache= curl_exit= domain= etag= etag_temp= n=0 response_code= temp= url=
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net comment
	# Passlist router and reserved IP addresses:
	echo "$passlist_router" | tr -d '\t' | filter_IP_Line | ipset restore -!
	# Passlist ip:
	echo "$passlist_ip" | filter_IP_CIDR | filter_Out_PrivateIP | awk '!x[$0]++' | awk '{printf "add Skynet-Temp %s comment \"Passlist: %s\"\n", $1, $1}' | ipset restore -!
	# Passlist domain:
	for domain in $(echo "$passlist_domain" | filter_Domain | awk '!x[$0]++'); do
		lookup_Domain "$domain" | filter_Out_PrivateIP | awk -v domain="$domain" '{printf "add Skynet-Temp %s comment \"Passlist: %s\"\n", $1, domain}' | ipset restore -! &
		n=$((n + 1)); if [ $((n % 50)) -eq 0 ]; then wait; fi
	done
	wait
	# Passlist root hints:
	url="http://www.internic.net/domain/named.root"
	temp="$dir_temp/namedroot"; touch "$temp"
	cache="$dir_cache/namedroot"
	etag_temp="$dir_temp/namedroot_etag"
	etag="$dir_etag/namedroot"; touch "$etag"

	response_code=$(curl -sf --location \
		--limit-rate "$throttle" --user-agent "$useragent" \
		--connect-timeout 5 --retry 3 --retry-max-time 60 \
		--remote-time --time-cond "$cache" \
		--etag-compare "$etag" --etag-save "$etag_temp" \
		--write-out "%{response_code}" --output "$temp" \
		--header "Accept-encoding: gzip" "$url"); curl_exit=$?

	if [ "$response_code" = "200" ] || [ "$response_code" = "304" ]; then
		mv -f "$temp" "$cache"
		mv -f "$etag_temp" "$etag"
	else
		log_Skynet "$(download_Error $curl_exit $response_code) $url"
	fi
	if [ -f "$cache" ]; then
		{ gunzip -c "$cache" 2>/dev/null || cat "$cache"; } | filter_IP_CIDR | filter_Out_PrivateIP | awk '!x[$0]++' | awk '{printf "add Skynet-Temp %s comment \"Passlist: Root hints\"\n", $1}' | ipset restore -!
	fi
	rm -f "$temp" "$etag_temp";
	ipset swap "Skynet-Passlist" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
	hash_Set "$passlist_router $passlist_ip $passlist_domain" "passlist"
}


load_Blocklist() {
	if hash_Unmodified "$blocklist_ip" "blocklist_ip"; then return; fi
	log_Skynet "[i] Update $(lookup_Comment 'Skynet-Blocklist')"
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net comment
	echo "$blocklist_ip" | filter_IP_CIDR | filter_Out_PrivateIP | awk '!x[$0]++' | awk '{printf "add Skynet-Temp %s comment \"Blocklist: %s\"\n", $1, $1}' | ipset restore -!
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


load_Set() {
	grep -E '^[+][0-9]' < "$dir_temp/diff" | cut -c2- > "$dir_temp/add"
	grep -E '^[-][0-9]' < "$dir_temp/diff" | cut -c2- > "$dir_temp/del"
	awk -v setname="$setname" -v comment="$comment" '{printf "add %s %s comment \"Blocklist: %s\"\n", setname, $1, comment}' "$dir_temp/add" | ipset restore -!
	awk -v setname="$setname" '{printf "del %s %s\n", setname, $1}' "$dir_temp/del" | ipset restore -!
	printf '%s | %6s | %7s | %7s |\n' \
		"$(date '+%b %d %T')" \
		"$(wc -l < "$filtered_temp")" \
		"-$(wc -l < "$dir_temp/del")" \
		"+$(wc -l < "$dir_temp/add")" >> "$dir_debug/$comment.log"
	update_Counter "$dir_update/$setname" >/dev/null
	rm -f "$dir_temp/diff" "$dir_temp/add" "$dir_temp/del"
	log_Tail "$dir_debug/$comment.log"
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
	{ gunzip -c "$temp" 2>/dev/null || cat "$temp"; } | filter_IP_CIDR | filter_Out_PrivateIP | sort -u > "$filtered_temp"
	diff "$filtered_cache" "$filtered_temp" > "$dir_temp/diff"; local diff_exit=$?
	printf '\033[1A\033[K' # cursor up and clear
	return $diff_exit
}


download_Set() {
	local cache= comment= curl_exit= dir= etag= etag_temp= filtered_cache= filtered_temp= line= list= lookup= setname= response_code= temp= update_cycles= url=
	echo "$blocklist_set" | filter_URL_Line > "$dir_temp/blocklist_set"

	while IFS= read -r line; do
		url=$(echo "$line" | filter_URL)
		comment=$(echo "$line" | filter_Comment || echo "<$(basename "$url")>" | filter_Comment)
		update_cycles=$(echo "$line" | filter_Update_Cycles || echo 4)
		setname="Skynet-$(echo -n "$url" | md5sum | cut -c1-24)"
		echo "$setname,$comment" >> "$dir_temp/lookup.csv"

		if ! ipset -n list "$setname" >/dev/null 2>&1; then
			ipset create "$setname" hash:net maxelem 524288 comment
			ipset add Skynet-Primary "$setname" comment "$comment"
		fi
		if [ -f "$dir_reload/$setname" ]; then
			if [ $(head -1 "$dir_reload/$setname" 2>/dev/null) -ge 27 ]; then
				update_cycles=24
			elif [ $(head -1 "$dir_reload/$setname" 2>/dev/null) -ge 4 ]; then
				update_cycles=4
			else
				update_cycles=1
			fi
		fi
		if [ $((updatecount % update_cycles)) -ne 0 ]; then
			continue
		fi

		echo " [i] Download $comment"
		temp="$dir_temp/${setname}_unfiltered"; touch "$temp"
		cache="$dir_cache/$setname"
		etag_temp="$dir_temp/${setname}_etag"
		etag="$dir_etag/$setname"; touch "$etag"
		filtered_temp="$dir_temp/${setname}_filtered"
		filtered_cache="$dir_filtered/$setname"

		response_code=$(curl -sf --location \
			--limit-rate "$throttle" --user-agent "$useragent" \
			--connect-timeout 5 --retry 3 --retry-max-time 60 \
			--remote-time --time-cond "$cache" \
			--etag-compare "$etag" --etag-save "$etag_temp" \
			--write-out "%{response_code}" --output "$temp" \
			--header "Accept-encoding: gzip" "$url"); curl_exit=$?
		printf '\033[1A\033[K' # cursor up and clear

		if [ $curl_exit -eq 0 ]; then
			if [ "$response_code" = "304" ]; then
				log_Skynet "[i] Fresh $comment"
			elif compare_Set && [ -s "$cache" ]; then
				log_Skynet "[!] Redownload $comment"
				mv -f "$temp" "$cache"
				mv -f "$filtered_temp" "$filtered_cache"
				mv -f "$etag_temp" "$etag"
			else
				log_Skynet "[i] Update $comment"
				load_Set
				mv -f "$temp" "$cache"
				mv -f "$filtered_temp" "$filtered_cache"
				mv -f "$etag_temp" "$etag"
			fi
			rm -f "$dir_reload/$setname"
		else
			log_Skynet "$(download_Error $curl_exit $response_code) $url"
			if [ "$response_code" = "429" ]; then
				echo "99" > "$dir_reload/$setname"
			else
				update_Counter "$dir_reload/$setname" >/dev/null
			fi
		fi
		rm -f "$temp" "$filtered_temp" "$etag_temp"
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
	for dir in "$dir_cache" "$dir_etag" "$dir_filtered" "$dir_reload" "$dir_update"; do
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


command="$1"
option="$2"
throttle=0
updatecount=0
iotblocked="disabled"
version="3.7.1"
useragent="$(curl -V | grep -Eo '^curl.+)') Skynet-Lite/$version https://github.com/wbartels/IPSet_ASUS_Lite"
lockfile="/var/lock/skynet.lock"

dir_skynet="/tmp/skynet"
dir_cache="$dir_skynet/cache"
dir_debug="$dir_skynet/debug"
dir_etag="$dir_skynet/etag"
dir_filtered="$dir_skynet/filtered"
dir_reload="$dir_skynet/reload"
dir_system="$dir_skynet/system"
dir_temp="$dir_skynet/temp"
dir_update="$dir_skynet/update_" # with firmware 386.1 directory 'update' will be deleted after 24 hours!
mkdir -p "$dir_cache" "$dir_debug" "$dir_etag" "$dir_filtered"
mkdir -p "$dir_reload" "$dir_system" "$dir_temp" "$dir_update"


domain=$(echo "$command" | is_Domain) && command="domain"
ip=$(echo "$command" | is_IP) && command="ip"
if ! ipset list -n Skynet-Primary >/dev/null 2>&1; then
	command="reset"
	option=""
fi


i=0
while [ "$(nvram get ntp_ready)" != "1" ] && [ "$command" != "uninstall" ]; do
	if [ $i -eq 0 ]; then log_Skynet "[i] Waiting for NTP to sync..."; fi
	if [ $i -eq 300 ]; then log_Skynet "[*] NTP failed to start after 5 minutes - Please fix immediately!"; echo; exit 1; fi
	i=$((i + 1)); sleep 1
done


if [ "$command" = "update" ] || [ "$command" = "reset" ]; then
	for i in 1 2 3 4 5 6; do
		if ping -q -w1 -c1 ibm.com >/dev/null 2>&1; then break; fi
		if ping -q -w1 -c1 fastly.com >/dev/null 2>&1; then break; fi
		if ping -q -w1 -c1 github.com >/dev/null 2>&1; then break; fi
		if [ $i -eq 1 ]; then log_Skynet "[!] Waiting for internet connectivity..."; fi
		if [ $i -eq 6 ]; then log_Skynet "[*] Internet connectivity error"; echo; exit 1; fi
		sleep 9
	done
fi


exec 99>"$lockfile"
if ! flock -n 99; then
	if [ "$command" = "update" ] && [ "$option" = "cru" ]; then
		log_Skynet "[!] Skynet Lite is locked, next update scheduled"
		exit 1;
	fi
	printf '\n\033[1A' # newline and cursor up
	printf '[i] Skynet Lite is locked, retry command every 2 seconds...'
	sleep 2
	exec "$0" "$command"
fi


if [ "$command" = "update" ] && [ "$option" = "cru" ]; then
	throttle="5M"
	updatecount=$(update_Counter "$dir_system/updatecount")
fi


if [ "$(nvram get wan0_proto)" = "pppoe" ]; then
	iface="ppp0"
else
	iface="$(nvram get wan0_ifname)"
fi


cp "$dir_system/lookup.csv" "$dir_temp/lookup.csv"
unset i


#######################
#- Start Skynet Lite -#
#######################


case "$command" in
	reset)
		header "Reset"
		log_Skynet "[i] Install"
		cru d Skynet_update; minutes=$(($(date +%M) % 15))
		rm -f "$dir_cache/"* "$dir_debug/"* "$dir_etag/"* "$dir_filtered/"*
		rm -f "$dir_reload/"* "$dir_system/"* "$dir_temp/"* "$dir_update/"*
		true > "$dir_skynet/warning.log"
		true > "$dir_skynet/error.log"
		touch "$dir_system/installtime"
		if [ "$0" != "/jffs/scripts/firewall" ]; then
			mv -f "$0" "/jffs/scripts/firewall"
			log_Skynet "[!] Skynet Lite moved to /jffs/scripts/firewall"
		fi
		if [ ! -f "/jffs/scripts/firewall-start" ]; then
			echo "#!/bin/sh
			/jffs/scripts/firewall" | tr -d '\t' > "/jffs/scripts/firewall-start"
			chmod 755 "/jffs/scripts/firewall-start"
		elif [ -f "/jffs/scripts/firewall-start" ] && ! grep -q "/jffs/scripts/firewall" "/jffs/scripts/firewall-start"; then
			chmod 755 "/jffs/scripts/firewall-start"
			echo "/jffs/scripts/firewall" >> "/jffs/scripts/firewall-start"
		fi
		unload_IPTables
		unload_LogIPTables
		unload_IPSets
		echo 'create Skynet-Passlist hash:net comment
			create Skynet-Primary list:set size 64 comment counters
			create Skynet-Blocklist hash:net comment
			create Skynet-Domain hash:net comment
			add Skynet-Primary Skynet-Blocklist comment "blocklist_ip"
			add Skynet-Primary Skynet-Domain comment "blocklist_domain"' | tr -d '\t' | ipset restore -!
		load_IPTables
		load_LogIPTables
		lookup_Comment_Init
		load_Passlist
		load_Blocklist
		load_Domain
		download_Set
		cru a Skynet_update "$((minutes + 0)),$((minutes + 15)),$((minutes + 30)),$((minutes + 45)) * * * * nice -n 19 /jffs/scripts/firewall update cru"
		update_Counter "$dir_system/updatecount" >/dev/null
		footer
	;;


	update)
		header "Update"
		lookup_Comment_Init
		load_Passlist
		load_Blocklist
		load_Domain
		download_Set
		footer
	;;


	uninstall)
		header "Uninstall"
		log_Skynet "[*] Uninstall Skynet Lite..."
		cru d Skynet_update
		if [ -f "/jffs/scripts/firewall-start" ]; then
			chmod 755 "/jffs/scripts/firewall-start"
			config=$(grep -v "/jffs/scripts/firewall" "/jffs/scripts/firewall-start")
			echo "$config" > "/jffs/scripts/firewall-start"
		fi
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
			sec=-1
			n=$(head -1 "$dir_update/$setname" 2>/dev/null)
			if [ "$n" -gt 0 ] 2>/dev/null; then
				sec=$(($(file_Age "$dir_system/installtime") / n))
			fi
			echo "$comment,$(formatted_Time "$sec"),$sec" >> "$dir_temp/file.csv"
		done
		sort -t, -k3n < "$dir_temp/file.csv" | awk -F, '{printf " %-40s  %15s\n", $1, $2}'
		footer
	;;


	entries)
		header "List" "Number of entries"
		true > "$dir_temp/file.ssv" # semicolon separated value
		while IFS=, read -r setname comment; do
			n=$(ipset -t list "$setname" | grep -F 'Number of entries' | grep -Eo '[0-9]+')
			echo "$comment;$n;$(formatted_Number $n)" >> "$dir_temp/file.ssv"
		done < "$dir_system/lookup.csv"
		sort -t';' -k2nr < "$dir_temp/file.ssv" | awk -F';' '{printf " %-40s  %15s\n", $1, $3}'
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
		true > "$dir_temp/file.ssv" # semicolon separated value
		ipset list Skynet-Primary | filter_Skynet | awk '{print $1 "," $3}' | while IFS=, read -r setname blocked; do
			echo "$(lookup_Comment "$setname");$blocked;$(formatted_Number $blocked)" >> "$dir_temp/file.ssv"
		done
		sort -t';' -k2nr -k1,1 < "$dir_temp/file.ssv" | awk -F';' '{printf " %-40s  %15s\n", $1, $3}'
		footer
	;;
esac


rm -f "$dir_temp/"*
log_Tail "$dir_skynet/warning.log"
log_Tail "$dir_skynet/error.log"

