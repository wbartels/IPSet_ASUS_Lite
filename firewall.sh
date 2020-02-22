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
#   Code based on Skynet By Adamm
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
# firewall 192.168.1.1
# firewall fresh
# firewall update
# firewall error
# firewall reset
# firewall uninstall
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


filtertraffic="all"
logmode="enabled"
loginvalid="disabled"


blacklist_set="		<binarydefense_atif>			https://www.binarydefense.com/banlist.txt  {1}
					<blocklist_de>					https://lists.blocklist.de/lists/all.txt  {1}
					<cleantalk_1day>				https://iplists.firehol.org/files/cleantalk_1d.ipset
					<dshield>						https://iplists.firehol.org/files/dshield.netset  {1}
					<greensnow>						https://iplists.firehol.org/files/greensnow.ipset  {1}
					<maxmind_proxy_fraud>			https://iplists.firehol.org/files/maxmind_proxy_fraud.ipset  {12}
					<myip>							https://www.myip.ms/files/blacklist/csf/latest_blacklist.txt  {1}
					<normshield_high_attack>		https://iplists.firehol.org/files/normshield_high_attack.ipset
					<normshield_high_bruteforce>	https://iplists.firehol.org/files/normshield_high_bruteforce.ipset
					<normshield_high_suspicious>	https://iplists.firehol.org/files/normshield_high_suspicious.ipset
					<normshield_high_webscan>		https://iplists.firehol.org/files/normshield_high_webscan.ipset
					<spamhaus_drop>					https://www.spamhaus.org/drop/drop.txt  {12}
					<spamhaus_edrop>				https://www.spamhaus.org/drop/edrop.txt  {12}
					<stopforumspam_1day>			https://iplists.firehol.org/files/stopforumspam_1d.ipset  {1}
					<stopforumspam_toxic>			https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt  {1}
					<talosintel>					https://iplists.firehol.org/files/talosintel_ipfilter.ipset  {1}
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
updatecount=0
iotblocked="disabled"

dir_skynet="/tmp/skynet"
dir_cache1="$dir_skynet/cache1"
dir_cache2="$dir_skynet/cache2"
dir_reload="$dir_skynet/reload"
dir_system="$dir_skynet/system"
file_errorlog="$dir_skynet/error.log"
file_installtime="$dir_system/installtime"
file_ipset="$dir_system/ipset"
file_sleep="$dir_system/sleep"
file_temp="$dir_system/temp"
file_updatecount="$dir_system/updatecount"
mkdir -p "$dir_cache1" "$dir_cache2" "$dir_reload" "$dir_system"


if ! ipset list -n Skynet-Master >/dev/null 2>&1; then
	command="reset"
fi


i=0
while [ "$(nvram get ntp_ready)" = "0" ]; do
	if [ $i -eq 0 ]; then logger -st Skynet "[i] Waiting for NTP to sync..."; fi
	if [ $i -eq 300 ]; then
		logger -st Skynet "[*] NTP failed to start after 5 minutes - Please fix immediately!";
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
		if [ $i -eq 1 ]; then logger -st Skynet "[*] Waiting for internet connectivity..."; fi
		if [ $i -eq 6 ]; then
			logger -st Skynet "[*] Internet connectivity error"
			echo "$(date) | Internet connectivity error" >> "$file_errorlog"
			touch "$dir_reload/all"
			echo; exit 1
		fi
		sleep 7
	done
fi


if [ "$command" = "update" ] && [ "$option" = "cru" ]; then
	if ! sleep=$(head -1 "$file_sleep" 2>/dev/null); then
		sleep=$(($(printf '%d' 0x$(openssl rand 1 -hex)) / 5 + 4)) # 0..255 / 5 + 4
		echo "$sleep" > "$file_sleep"
	fi
	sleep $sleep
fi


lockfile="/tmp/var/lock/skynet.lock"
exec 99>$lockfile
flock -n 99
if [ $? -ne 0 ]; then
	echo "An instance of Skynet Lite is already running"; echo; exit 1
fi


if [ "$(nvram get wan0_proto)" = "pppoe" ]; then
	iface="ppp0"
else
	iface="$(nvram get wan0_ifname)"
fi


unset i sleep


###############
#- Functions -#
###############


unload_IPTables () {
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


load_IPTables () {
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
		iptables -t raw -I PREROUTING -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j DROP 2>/dev/null
	fi
	if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
		iptables -t raw -I PREROUTING -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
		iptables -t raw -I OUTPUT -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j DROP 2>/dev/null
	fi
	if [ "$(nvram get sshd_enable)" = "1" ] && [ "$(nvram get sshd_bfp)" = "1" ] && [ "$(uname -o)" = "ASUSWRT-Merlin" ] && [ "$(nvram get switch_wantag)" != "movistar" ]; then
		local pos1="$(iptables --line -nL SSHBFP | grep -F "seconds: 60 hit_count: 4" | grep -E 'DROP|logdrop' | awk '{print $1}')"
		iptables -I SSHBFP "$pos1" -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j SET --add-set Skynet-Blacklist src 2>/dev/null
		iptables -I SSHBFP "$pos1" -m recent --update --seconds 60 --hitcount 4 --name SSH --rsource -j LOG --log-prefix "[BLOCKED - NEW BAN] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	fi
}


unload_LogIPTables () {
	iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -t raw -D PREROUTING -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -t raw -D OUTPUT -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -D logdrop -m state --state NEW -j LOG --log-prefix "[BLOCKED - INVALID] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
	iptables -D FORWARD -i br0 -m set --match-set Skynet-IOT src ! -o tun2+ -j LOG --log-prefix "[BLOCKED - IOT] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
}


load_LogIPTables () {
	if [ "$logmode" = "enabled" ]; then
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "inbound" ]; then
			local pos2="$(iptables --line -nL PREROUTING -t raw | grep -F "Skynet-Master src" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos2" -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
		if [ "$filtertraffic" = "all" ] || [ "$filtertraffic" = "outbound" ]; then
			local pos3="$(iptables --line -nL PREROUTING -t raw | grep -F "Skynet-Master dst" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I PREROUTING "$pos3" -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
			local pos4="$(iptables --line -nL OUTPUT -t raw | grep -F "Skynet-Master dst" | grep -F "DROP" | awk '{print $1}')"
			iptables -t raw -I OUTPUT "$pos4" -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
		if [ "$(nvram get fw_log_x)" = "drop" ] || [ "$(nvram get fw_log_x)" = "both" ] && [ "$loginvalid" = "enabled" ]; then
			iptables -I logdrop -m state --state NEW -j LOG --log-prefix "[BLOCKED - INVALID] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
		if [ "$iotblocked" = "enabled" ]; then
			local pos5="$(iptables --line -nL FORWARD | grep -F "Skynet-IOT" | grep -F "DROP" | awk '{print $1}')"
			iptables -I FORWARD "$pos5" -i br0 -m set --match-set Skynet-IOT src ! -o tun2+ -j LOG --log-prefix "[BLOCKED - IOT] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
	fi
}


unload_IPSets () {
	ipset -q destroy Skynet-Master
	ipset -q destroy Skynet-Blacklist
	ipset -q destroy Skynet-Domain
	ipset -q destroy Skynet-ASN
	ipset -q destroy Skynet-Temp
	ipset -q destroy Skynet-Whitelist
	ipset list -n | filter_Skynet_Set | xargs -I setname ipset -q destroy setname
}


log_Skynet () {
	logger -t Skynet "$1"; echo " $1"
}


domain_Lookup () {
	set -o pipefail; nslookup "$1" 2>/dev/null | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | awk 'NR>2'
	if [ $? -ne 0 ]; then
		log_Skynet "[*] DNS lookup failed for $1"
		echo "$(date) | DNS lookup failed | $1" >> "$file_errorlog"
	fi
}


filter_Domain () {
	grep -oE '([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]'
}


strip_Domain () {
	grep -oE 'https?://\S+' | cut -d'/' -f3 | awk '!x[$0]++'
}


filter_URL () {
	grep -oE 'https?://\S+'
}


filter_URL_Line () {
	grep -E 'https?://\S+'
}


filter_Comment () {
	grep -oE '<.+>' | tr -d '<>' | tr ' ' '_'
}


filter_Update_Cycles () {
	grep -oE '\{[0-9]+\}' | tr -d '{}'
}


filter_IP_CIDR () {
	grep -oE '\b(((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3})(\/(3[0-2]|[12]?[0-9]))?)\b'
}


filter_IP_Line () {
	grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
}


filter_ASN () {
	grep -oE 'AS[1-9][0-9]{2,9}'
}


filter_Skynet () {
	grep  -E '^Skynet-'
}


filter_Skynet_Set () {
	grep -E '^Skynet-[0-9a-f]{24}'
}


is_IP () {
	grep -oE '^((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3})$'
}


lan_CIDR_Lookup () {
	if [ "$(echo "$1" | cut -c1-8)" = "192.168." ];	then
		echo "192.168.0.0/16"
	elif [ "$(echo "$1" | cut -c1-4)" = "172." ]; then
		echo "172.16.0.0/12"
	elif [ "$(echo "$1" | cut -c1-3)" = "10." ]; then
		echo "10.0.0.0/8";
	fi
}


file_Age () {
	local sec=$(($(date +%s) - $(date +%s -r "$1" 2>/dev/null || date +%s)))
	if [ $sec -lt 86400 ]; then
		printf '%02d:%02d' $(($sec/3600)) $(($sec%3600/60))
	elif [ $sec -lt 172800 ]; then
		printf '1 day %02d:%02d' $(($sec%86400/3600)) $(($sec%3600/60))
	else
		printf '%d days %02d:%02d' $(($sec/86400)) $(($sec%86400/3600)) $(($sec%3600/60))
	fi
}


load_Whitelist () {
	[ $((updatecount % 48)) -ne 0 ] && return
	log_Skynet "[i] Update whitelist"
	true > "$file_ipset"
	# Whitelist router:
	echo "add Skynet-Temp 127.0.0.0/8 comment \"Whitelist: loopback_ipaddr\"
	add Skynet-Temp $(lan_CIDR_Lookup $(nvram get lan_ipaddr)) comment \"Whitelist: lan_ipaddr\"
	add Skynet-Temp $(nvram get wan0_ipaddr) comment \"Whitelist: wan0_ipaddr\"
	add Skynet-Temp $(nvram get wan0_gateway) comment \"Whitelist: wan0_gateway\"
	add Skynet-Temp $(nvram get wan0_dns | awk '{print $1}') comment \"Whitelist: wan0_dns\"
	add Skynet-Temp $(nvram get wan0_dns | awk '{print $2}') comment \"Whitelist: wan0_dns\"
	add Skynet-Temp $(nvram get dhcp_dns1_x) comment \"Whitelist: dhcp_dns1_x\"
	add Skynet-Temp $(nvram get dhcp_dns2_x) comment \"Whitelist: dhcp_dns2_x\"" | tr -d '\t' | filter_IP_Line >> "$file_ipset"
	# Whitelist ip:
	echo "$whitelist_ip" | filter_IP_CIDR | awk '{printf "add Skynet-Temp %s comment \"Whitelist: %s\"\n", $1, $1}' >> "$file_ipset"
	# Whitelist domain:
	local domain n=0
	for domain in $(echo "internic.net ipinfo.io $whitelist_domain $(echo "$blacklist_set" | strip_Domain) $(nvram get ntp_server0) $(nvram get ntp_server1)" | filter_Domain); do
		domain_Lookup "$domain" | awk -v domain="$domain" '{printf "add Skynet-Temp %s comment \"Whitelist: %s\"\n", $1, domain}' >> "$file_ipset" &
		n=$((n + 1)); [ $((n % 50)) -eq 0 ] && wait
	done
	wait
	# Whitelist root hints:
	local file="$dir_cache2/named.root"
	local response_code
	if response_code=$(curl -fsL --retry 4 "http://www.internic.net/domain/named.root" --output "$file_temp" --time-cond "$file" --write-out "%{response_code}") && [ "$response_code" = "200" ]; then
		mv -f "$file_temp" "$file"
	fi
	if [ -f "$file" ]; then
		< "$file" filter_IP_CIDR | awk '{printf "add Skynet-Temp %s comment \"Whitelist: Root hints\"\n", $1}' >> "$file_ipset"
	fi
	# Swap to Skynet-Whitelist:
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net hashsize "$(($(wc -l < "$file_ipset") + 8))" comment
	ipset restore -! -f "$file_ipset"
	ipset swap "Skynet-Whitelist" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
}


load_Blacklist () {
	[ "$option" = "cru" ] && return
	log_Skynet "[i] Update blacklist_ip/cidr"
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net hashsize "$(($(echo "$blacklist_ip" | wc -l) + 8))" comment
	echo "$blacklist_ip" | filter_IP_CIDR | awk '{printf "add Skynet-Temp %s comment \"Blacklist: %s\"\n", $1, $1}' | ipset restore -!
	ipset swap "Skynet-Blacklist" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
}


load_Domain () {
	[ $((updatecount % 48)) -ne 0 ] && return
	log_Skynet "[i] Update blacklist_domain"
	true > "$file_ipset"
	local domain n=0
	for domain in $(echo "$blacklist_domain" | filter_Domain); do
		domain_Lookup "$domain" | awk -v domain="$domain" '{printf "add Skynet-Temp %s comment \"Blacklist: %s\"\n", $1, domain}' >> "$file_ipset" &
		n=$((n + 1)); [ $((n % 50)) -eq 0 ] && wait
	done
	wait
	ipset -q destroy "Skynet-Temp"
	ipset create Skynet-Temp hash:net hashsize "$(($(wc -l < "$file_ipset") + 8))" comment
	ipset restore -! -f "$file_ipset"
	ipset swap "Skynet-Domain" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
}


load_ASN () {
	[ $((updatecount % 48)) -ne 0 ] && [ ! -f "$dir_reload/asn" ] && return
	log_Skynet "[i] Update blacklist_asn"
	rm -f "$dir_reload/asn"
	true > "$file_ipset"
	local asn n=0
	for asn in $(echo "$blacklist_asn" | filter_ASN); do
		(	# Subshell
			set -o pipefail; curl -fsL --retry 4 "https://ipinfo.io/$asn" | filter_IP_CIDR | awk -v asn="$asn" '{printf "add Skynet-Temp %s comment \"Blacklist: %s\"\n", $1, asn}' | awk '!x[$0]++' >> "$file_ipset"
			if [ $? -ne 0 ]; then
				log_Skynet "[*] Download error https://ipinfo.io/$asn"
				echo "$(date) | Download error | https://ipinfo.io/$asn" >> "$file_errorlog"
				touch "$dir_reload/asn"
			fi
		) &
		n=$((n + 1)); [ $((n % 10)) -eq 0 ] && wait
		[ -f "$dir_reload/asn" ] && return
	done
	wait
	[ -f "$dir_reload/asn" ] && return
	ipset -q destroy "Skynet-Temp"
	ipset create "Skynet-Temp" hash:net hashsize "$(($(wc -l < "$file_ipset") + 8))" comment
	ipset restore -! -f "$file_ipset"
	ipset swap "Skynet-ASN" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
}


load_Set () {
	log_Skynet "[i] Update $comment"
	# Use global setname, comment and file
	if ! ipset list -n "$setname" >/dev/null 2>&1; then
		ipset create "$setname" hash:net hashsize 64 maxelem 262144 comment
		ipset add Skynet-Master "$setname" comment "$comment"
	fi
	ipset -q destroy "Skynet-Temp"
	ipset create "Skynet-Temp" hash:net hashsize "$(($(wc -l < "$file") + 8))" maxelem 262144 comment
	< "$file" filter_IP_CIDR | awk -v comment="$comment" '{printf "add Skynet-Temp %s comment \"Blacklist: %s\"\n", $1, comment}' | ipset restore -!
	ipset swap "$setname" "Skynet-Temp"
	ipset destroy "Skynet-Temp"
}


download_Set () {
	echo "$blacklist_set" | filter_URL_Line | while IFS= read -r line; do
		# Subshell
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

		file="$dir_cache1/$setname"
		if response_code=$(curl -fsL --retry 4 $url --output "$file_temp" --time-cond "$file" --write-out "%{response_code}") && [ "$response_code" = "200" ]; then
			mv -f "$file_temp" "$file"
			load_Set
		elif [ "$response_code" = "304" ] && ! ipset list -n "$setname" >/dev/null 2>&1; then
			load_Set
		elif [ "$response_code" = "304" ]; then
			log_Skynet "[-] Fresh $comment"
		else
			log_Skynet "[*] Download error $url"
			echo "$(date) | Download error | $response_code | $url" >> "$file_errorlog"
			touch "$dir_reload/$setname"
		fi
	done

	# Unload unlisted set
	[ "$option" = "cru" ] && return
	local lookup=$(ipset list Skynet-Master | filter_Skynet_Set | tr -d '"' | awk '{print $1, $7}')
	local url list="" setname dir
	for url in $(echo "$blacklist_set" | filter_URL); do
		list="$list Skynet-$(echo -n "$url" | md5sum | cut -c1-24)"
	done
	for setname in $(echo "$lookup" | sort -k2 | awk '{print $1}'); do
		if ! echo "$list" | grep -q "$setname"; then
			log_Skynet "[*] Unload $(echo "$lookup" | awk -v setname="$setname" '$1 == setname {print $2}')"
			ipset -q del "Skynet-Master" "$setname"
			ipset -q destroy "$setname"
		fi
	done
	cd "$dir_cache1"
	for setname in $(ls -1t); do
		if ! echo "$list" | grep -q "$setname"; then
			rm -f "$dir/$setname"
		fi
	done
}


header () {
	[ "$option" = "cru" ] && return
	clear
	sed -n '2,7s/#//p' "$0"
	echo " Skynet Lite by Willem Bartels"
	echo " Code based on Skynet By Adamm"
	echo
	if [ -n "$1" ] || [ -n "$2" ]; then
		echo "-----------------------------------------------------------"
		printf " %-25s  %30s\n" "$1" "$2"
		echo "-----------------------------------------------------------"
	fi
}


footer () {
	[ "$option" = "cru" ] && return
	echo "-----------------------------------------------------------"
	printf " %-25s  %30s\n\n" "Uptime $(file_Age "$file_installtime")" "$(if [ $(ls -1 "$dir_reload" | wc -l) -ge 1 ]; then echo "[i] Failed downloads queued"; fi)"
}


#######################
#- Start Skynet Lite -#
#######################


ip=$(echo "$command" | is_IP) || ip="noip"
case "$command" in
	reset)
		header "Reset"
		log_Skynet "[i] Install"
		rm -f "$dir_system/"*
		rm -f "$dir_reload/"*
		touch "$file_installtime"
		touch "$file_errorlog"
		echo 0 > "$file_updatecount"
		if [ "$0" != "/jffs/scripts/firewall" ]; then
			mv -f "$0" "/jffs/scripts/firewall"
			log_Skynet "[*] Skynet Lite moved to /jffs/scripts/firewall"
		fi
		if [ ! -f "/jffs/scripts/firewall-start" ]; then
			echo "#!/bin/sh
			sh /jffs/scripts/firewall" | tr -d '\t' > "/jffs/scripts/firewall-start"
			chmod 755 "/jffs/scripts/firewall-start"
		elif [ -f "/jffs/scripts/firewall-start" ] && ! grep -q "/jffs/scripts/firewall" "/jffs/scripts/firewall-start"; then
			chmod 755 "/jffs/scripts/firewall-start"
			echo "sh /jffs/scripts/firewall" >> "/jffs/scripts/firewall-start"
		fi
		rand=$(printf '%d' 0x$(openssl rand 1 -hex)) # 0..255
		m1=$((rand / 18 + 0));  m2=$((rand / 18 + 15))
		m3=$((rand / 18 + 30)); m4=$((rand / 18 + 45))
		cru d Skynet_update
		cru a Skynet_update "$m1,$m2,$m3,$m4 * * * * sh /jffs/scripts/firewall update cru"
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
		if [ "$option" = "cru" ] && [ ! -f "$dir_reload/all" ]; then
			updatecount=$(head -1 "$file_updatecount" 2>/dev/null)
			updatecount=$((updatecount + 1))
			echo "$updatecount" > "$file_updatecount"
		else
			rm -f "$dir_reload/"*
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


	error)
		header ""
		if [ -f "$file_errorlog" ] && [ $(wc -l < "$file_errorlog") -ge 1 ]; then
			cat "$file_errorlog"
		else
			echo "Empty error log"
		fi
		echo
	;;


	fresh)
		header "Blacklist" "Last download"
		lookup=$(ipset list Skynet-Master | filter_Skynet_Set | tr -d '"' | awk '{print $1, $7}')
		cd "$dir_cache1"
		for setname in $(ls -1t | filter_Skynet_Set); do
			printf " %-40s  %15s\n" "$(echo "$lookup" | awk -v setname="$setname" '$1 == setname {print $2}')" "$(file_Age "$dir_cache1/$setname")"
		done
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
		header "Blacklist" "Blocked"
		ipset list Skynet-Master | filter_Skynet | tr -d '"' | sort -k3,3gr -k7,7 | awk '{printf " %-40s  %15s\n", $7, $3}'
		footer
	;;
esac
