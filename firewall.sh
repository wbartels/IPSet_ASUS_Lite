#!/bin/sh
#  ___ _                 _     _    _ _
# / __| |___  _ _ _  ___| |_  | |  (_) |_ ___
# \__ \ / / || | ' \/ -_)  _| | |__| |  _/ -_)
# |___/_\_\\_, |_||_\___|\__| |____|_|\__\___|
#          |__/
#
#   Skynet Lite by Willem Bartels
#   IP Blocking For ASUS Routers Using IPSet
#   https://github.com/wbartels/IPSet_ASUS
#
#   Code based on Skynet By Adamm
#   Advanced IP Blocking For ASUS Routers Using IPSet
#   https://github.com/Adamm00/IPSet_ASUS
#   This script will always be open source and free to use
#
#
# Installation:
# curl https://raw.githubusercontent.com/wbartels/IPSet_ASUS/master/firewall.sh --output /jffs/scripts/firewall && chmod 755 /jffs/scripts/firewall && sh /jffs/scripts/firewall
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
# The cron job is started every 15 minutes
# By default the blacklist_set update process is started after 4 cycles = 1 hour
# This value can be overruled per set with the {n} tag
# In case of a download error, this set is temporarily set to 1 cycle until a successful download
#
# Both the <comment> and {n} tag are optional
# The order of the url and tags are not important, but need to be on the same line
#


###################
#- Configuration -#
###################


filtertraffic="all"
logmode="enabled"
loginvalid="disabled"


blacklist_set="		<binarydefense_atif>			https://www.binarydefense.com/banlist.txt
					<blocklist_de>					https://lists.blocklist.de/lists/all.txt  {1}
					<cleantalk_1day>				https://iplists.firehol.org/files/cleantalk_1d.ipset  {1}
					<dshield>						https://iplists.firehol.org/files/dshield.netset  {1}
					<greensnow>						https://iplists.firehol.org/files/greensnow.ipset  {1}
					<maxmind_proxy_fraud>			https://iplists.firehol.org/files/maxmind_proxy_fraud.ipset
					<myip>							https://www.myip.ms/files/blacklist/csf/latest_blacklist.txt
					<normshield_high_attack>		https://iplists.firehol.org/files/normshield_high_attack.ipset
					<normshield_high_bruteforce>	https://iplists.firehol.org/files/normshield_high_bruteforce.ipset
					<normshield_high_suspicious>	https://iplists.firehol.org/files/normshield_high_suspicious.ipset
					<normshield_high_webscan>		https://iplists.firehol.org/files/normshield_high_webscan.ipset
					<spamhaus_drop>					https://www.spamhaus.org/drop/drop.txt  {12}
					<spamhaus_edrop>				https://www.spamhaus.org/drop/edrop.txt  {12}
					<stopforumspam_1day>			https://iplists.firehol.org/files/stopforumspam_1d.ipset  {1}
					<stopforumspam_toxic>			https://www.stopforumspam.com/downloads/toxic_ip_cidr.txt  {24}
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

dir_skynet="/tmp/skynet"
dir_cache="$dir_skynet/cache"
dir_retry="$dir_skynet/retry"
dir_system="$dir_skynet/system"
file_retryasn="$dir_system/retryasn"
file_temp="$dir_system/temp"
file_installtime="$dir_system/installtime"
file_updatecount="$dir_system/updatecount"
file_errorlog="$dir_skynet/error.log"
mkdir -p "$dir_cache" "$dir_retry" "$dir_system"


i=0
while [ "$(nvram get ntp_ready)" = "0" ]; do
		if [ $i -eq 0 ]; then logger -st Skynet "[i] Waiting for NTP to sync..."; fi
		if [ $i -eq 300 ]; then logger -st Skynet "[*] NTP failed to start after 5 minutes - Please fix immediately!"; echo; exit 1; fi
		i=$((i + 1)); sleep 1
done
if [ ! -f "$file_installtime" ]; then logger -st Skynet "[i] NTP sync time $i seconds"; fi


if [ "$command" = "update" ] || [ "$command" = "reset" ] || ! ipset list -n Skynet-Master >/dev/null 2>&1; then
		for i in 1 2 3 4 5 6; do
			if ping -q -w1 -c1 google.com >/dev/null 2>&1; then break; fi
			if ping -q -w1 -c1 github.com >/dev/null 2>&1; then break; fi
			if ping -q -w1 -c1 amazon.com >/dev/null 2>&1; then break; fi
			if [ $i -eq 1 ]; then logger -st Skynet "[*] Waiting for internet connectivity..."; fi
			if [ $i -eq 6 ]; then
				logger -st Skynet "[*] Internet connectivity error"
				touch "$file_errorlog"; echo "$(date) | Internet connectivity error" >> "$file_errorlog"
				echo; exit 1
			fi
			sleep 7
		done
fi
unset i


if [ "$command" = "update" ] && [ "$option" = "cru" ] && [ $(($(date +%s) % 60)) -lt 10 ]; then
		rand=$(printf '%d' 0x$(openssl rand 1 -hex)) # 0..255
		sleep $((rand / 5))
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


###############
#- Functions -#
###############


Unload_IPTables () {
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


Load_IPTables () {
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


Unload_LogIPTables () {
		iptables -t raw -D PREROUTING -i "$iface" -m set ! --match-set Skynet-Whitelist src -m set --match-set Skynet-Master src -j LOG --log-prefix "[BLOCKED - INBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		iptables -t raw -D PREROUTING -i br0 -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		iptables -t raw -D OUTPUT -m set ! --match-set Skynet-Whitelist dst -m set --match-set Skynet-Master dst -j LOG --log-prefix "[BLOCKED - OUTBOUND] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		iptables -D logdrop -m state --state NEW -j LOG --log-prefix "[BLOCKED - INVALID] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		iptables -D FORWARD -i br0 -m set --match-set Skynet-IOT src ! -o tun2+ -j LOG --log-prefix "[BLOCKED - IOT] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
}


Load_LogIPTables () {
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
			pos5="$(iptables --line -nL FORWARD | grep -F "Skynet-IOT" | grep -F "DROP" | awk '{print $1}')"
			iptables -I FORWARD "$pos5" -i br0 -m set --match-set Skynet-IOT src ! -o tun2+ -j LOG --log-prefix "[BLOCKED - IOT] " --log-tcp-sequence --log-tcp-options --log-ip-options 2>/dev/null
		fi
}


Unload_IPSets () {
		ipset -q destroy Skynet-Master
		ipset -q destroy Skynet-Whitelist
		ipset -q destroy Skynet-Blacklist
		ipset -q destroy Skynet-Domain
		ipset -q destroy Skynet-ASN
		ipset -q destroy Skynet-Temp
		ipset list -n | Filter_Skynet_Set | xargs -I setname ipset -q destroy setname
}


Domain_Lookup () {
		set -o pipefail; nslookup "$1" 2>/dev/null | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | awk 'NR>2'
		if [ $? -ne 0 ]; then
			logger -st Skynet "[*] DNS lookup failed for $1"
			touch "$file_errorlog"; echo "$(date) | DNS lookup failed | $1" >> "$file_errorlog"
		fi
}


Filter_Domain () {
		grep -oE '([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]'
}


Strip_Domain () {
		grep -oE 'https?://\S+' | cut -d'/' -f3 | awk '!x[$0]++'
}


Filter_URL () {
		grep -oE 'https?://\S+'
}


Filter_URL_Line () {
		grep -E 'https?://\S+'
}


Filter_Comment () {
		grep -oE '<.+>' | tr -d '<>' | tr ' ' '_'
}


Filter_Update_Cycles () {
		grep -oE '\{[0-9]+\}' | tr -d '{}'
}


Filter_IP_CIDR () {
		grep -oE '\b(((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3})(\/(3[0-2]|[12]?[0-9]))?)\b'
}


Filter_IP_Line () {
		grep -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
}


Filter_ASN () {
		grep -oE 'AS[1-9][0-9]{2,9}'
}


Filter_Skynet () {
		grep  -E '^Skynet-'
}


Filter_Skynet_Set () {
		grep -E '^Skynet-[0-9a-f]{24}'
}


Is_IP () {
		grep -oE '^((25[0-4]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[1-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])){3})$'
}


LAN_CIDR_Lookup () {
		if [ "$(echo "$1" | cut -c1-8)" = "192.168." ];	then
			echo "192.168.0.0/16"
		elif [ "$(echo "$1" | cut -c1-4)" = "172." ]; then
			echo "172.16.0.0/12"
		elif [ "$(echo "$1" | cut -c1-3)" = "10." ]; then
			echo "10.0.0.0/8";
		fi
}


File_Age () {
		sec=$(($(date +%s) - $(date +%s -r "$1" 2>/dev/null || date +%s)))
		if [ $sec -lt 86400 ]; then
			printf '%02d:%02d' $(($sec/3600)) $(($sec%3600/60))
		elif [ $sec -lt 172800 ]; then
			printf '1 day %02d:%02d' $(($sec%86400/3600)) $(($sec%3600/60))
		else
			printf '%d days %02d:%02d' $(($sec/86400)) $(($sec%86400/3600)) $(($sec%3600/60))
		fi
}


Load_Whitelist () {
		[ $((updatecount % 48)) -ne 0 ] && return
		logger -st Skynet "[i] Update whitelist"
		echo -n "" > "$file_temp"
		echo "add Skynet-Temp 127.0.0.0/8 comment \"Whitelist: loopback_ipaddr\"
		add Skynet-Temp $(LAN_CIDR_Lookup $(nvram get lan_ipaddr)) comment \"Whitelist: lan_ipaddr\"
		add Skynet-Temp $(nvram get wan0_ipaddr) comment \"Whitelist: wan0_ipaddr\"
		add Skynet-Temp $(nvram get wan0_gateway) comment \"Whitelist: wan0_gateway\"
		add Skynet-Temp $(nvram get wan0_dns | awk '{print $1}') comment \"Whitelist: wan0_dns\"
		add Skynet-Temp $(nvram get wan0_dns | awk '{print $2}') comment \"Whitelist: wan0_dns\"
		add Skynet-Temp $(nvram get dhcp_dns1_x) comment \"Whitelist: dhcp_dns1_x\"
		add Skynet-Temp $(nvram get dhcp_dns2_x) comment \"Whitelist: dhcp_dns2_x\"" | tr -d '\t' | Filter_IP_Line >> "$file_temp"
		echo "$whitelist_ip" | Filter_IP_CIDR | awk '{printf "add Skynet-Temp %s comment \"Whitelist: %s\"\n", $1, $1}' >> "$file_temp"
		whitelist_domain="$(nvram get ntp_server0) $(nvram get ntp_server1) $(echo "$blacklist_set" | Strip_Domain) $whitelist_domain"
		for domain in $(echo "$whitelist_domain" | Filter_Domain); do
			Domain_Lookup "$domain" | awk -v domain="$domain" '{printf "add Skynet-Temp %s comment \"Whitelist: %s\"\n", $1, domain}' >> "$file_temp" &
			n=$((n + 1)); [ $((n % 50)) -eq 0 ] && wait
		done
		wait
		hashsize=$((8 + $(wc -l < "$file_temp")))
		ipset -q destroy "Skynet-Temp"
		ipset create Skynet-Temp hash:net hashsize "$hashsize" comment
		ipset restore -! -f "$file_temp"
		ipset swap "Skynet-Whitelist" "Skynet-Temp"
		ipset destroy "Skynet-Temp"
}


Load_Blacklist () {
		[ "$option" = "cru" ] && return
		logger -st Skynet "[i] Update blacklist_ip/cidr"
		hashsize=$((8 + $(echo "$blacklist_ip" | wc -l)))
		ipset -q destroy "Skynet-Temp"
		ipset create Skynet-Temp hash:net hashsize "$hashsize" comment
		echo "$blacklist_ip" | Filter_IP_CIDR | awk '{printf "add Skynet-Temp %s comment \"Blacklist: %s\"\n", $1, $1}' | ipset restore -!
		ipset swap "Skynet-Blacklist" "Skynet-Temp"
		ipset destroy "Skynet-Temp"
}


Load_Domain () {
		[ $((updatecount % 48)) -ne 0 ] && return
		logger -st Skynet "[i] Update blacklist_domain"
		echo -n "" > "$file_temp"
		for domain in $(echo "$blacklist_domain" | Filter_Domain); do
			Domain_Lookup "$domain" | awk -v domain="$domain" '{printf "add Skynet-Temp %s comment \"Blacklist: %s\"\n", $1, domain}' >> "$file_temp" &
			n=$((n + 1)); [ $((n % 50)) -eq 0 ] && wait
		done
		wait
		hashsize=$((8 + $(wc -l < "$file_temp")))
		ipset -q destroy "Skynet-Temp"
		ipset create Skynet-Temp hash:net hashsize "$hashsize" comment
		ipset restore -! -f "$file_temp"
		ipset swap "Skynet-Domain" "Skynet-Temp"
		ipset destroy "Skynet-Temp"
}


Load_ASN () {
		[ $((updatecount % 48)) -ne 0 ] && [ ! -f "$file_retryasn" ] && return
		logger -st Skynet "[i] Update blacklist_asn"
		rm -f "$file_retryasn"
		echo -n "" > "$file_temp"
		for asn in $(echo "$blacklist_asn" | Filter_ASN); do
			(
				set -o pipefail; curl -fsL --retry 4 "https://ipinfo.io/$asn" | Filter_IP_CIDR | awk -v asn="$asn" '{printf "add Skynet-Temp %s comment \"Blacklist: %s\"\n", $1, asn}' | awk '!x[$0]++' >> "$file_temp"
				if [ $? -ne 0 ]; then
					logger -st Skynet "[*] Download error https://ipinfo.io/$asn"
					touch "$file_errorlog"; echo "$(date) | Download error | https://ipinfo.io/$asn" >> "$file_errorlog"
					touch "$file_retryasn"
				fi
			) &
			n=$((n + 1)); [ $((n % 10)) -eq 0 ] && wait
			[ -f "$file_retryasn" ] && return
		done
		wait
		[ -f "$file_retryasn" ] && return
		hashsize=$((8 + $(wc -l < "$file_temp")))
		ipset -q destroy "Skynet-Temp"
		ipset create "Skynet-Temp" hash:net hashsize "$hashsize" comment
		ipset restore -! -f "$file_temp"
		ipset swap "Skynet-ASN" "Skynet-Temp"
		ipset destroy "Skynet-Temp"
}


Load_Set () {
		setname="$1"; comment="$2"
		logger -st Skynet "[i] Update $comment"
		file="$dir_cache/$setname"
		hashsize=$((8 + $(wc -l < "$file")))
		if ! ipset list -n "$setname" >/dev/null 2>&1; then
			ipset create "$setname" hash:net hashsize "$hashsize" maxelem 262144 comment
			ipset add Skynet-Master "$setname" comment "$comment"
		fi
		ipset -q destroy "Skynet-Temp"
		ipset create "Skynet-Temp" hash:net hashsize "$hashsize" maxelem 262144 comment
		< "$file" Filter_IP_CIDR | awk -v comment="$comment" '{printf "add Skynet-Temp %s comment \"Blacklist: %s\"\n", $1, comment}' | ipset restore -!
		ipset swap "$setname" "Skynet-Temp"
		ipset destroy "Skynet-Temp"
}


Download_Set () {
		echo "$blacklist_set" | Filter_URL_Line | while IFS= read -r line; do
			url=$(echo "$line" | Filter_URL)
			comment=$(echo "$line" | Filter_Comment)
			update_cycles=$(echo "$line" | Filter_Update_Cycles)
			setname="Skynet-$(echo -n "$url" | md5sum | cut -c1-24)"

			if [ -z "$comment" ]; then
				comment=$(basename "$url")
			fi
			if [ -z "$update_cycles" ]; then
				update_cycles=4
			fi
			if [ -f "$dir_retry/$setname" ]; then
				update_cycles=1
				rm -f "$dir_retry/$setname"
			fi
			if [ $((updatecount % update_cycles)) -ne 0 ]; then
				continue
			fi

			file="$dir_cache/$setname"
			if response_code=$(curl -fsL --retry 4 $url --output "$file_temp" --time-cond "$file" --write-out "%{response_code}") && [ "$response_code" = "200" ]; then
				mv -f "$file_temp" "$file"
				Load_Set "$setname" "$comment"
			elif [ "$response_code" = "304" ] && ! ipset list -n "$setname" >/dev/null 2>&1; then
				Load_Set "$setname" "$comment"
			elif [ "$response_code" = "304" ]; then
				logger -st Skynet "[-] Fresh $comment"
			else
				logger -st Skynet "[*] Download error $url"
				touch "$file_errorlog"; echo "$(date) | Download error | $response_code | $url" >> "$file_errorlog"
				touch "$dir_retry/$setname"
			fi
		done

		# Unload unlisted set
		[ "$option" = "cru" ] && return
		lookup=$(ipset list Skynet-Master | Filter_Skynet_Set | tr -d '"' | awk '{print $1, $7}')
		list=""
		for url in $(echo "$blacklist_set" | Filter_URL); do
			list="$list Skynet-$(echo -n "$url" | md5sum | cut -c1-24)"
		done
		for setname in $(echo "$lookup" | sort -k2 | awk '{print $1}'); do
			if ! echo "$list" | grep -q "$setname"; then
				logger -st Skynet "[*] Unload $(echo "$lookup" | awk -v setname="$setname" '$1 == setname {print $2}')"
				ipset -q del "Skynet-Master" "$setname"
				ipset -q destroy "$setname"
			fi
		done
		for dir in "$dir_cache" "$dir_retry"; do
			cd "$dir"
			for setname in $(ls -1t); do
				if ! echo "$list" | grep -q "$setname"; then
					rm -f "$dir/$setname"
				fi
			done
		done
}


#######################
#- Start Skynet Lite -#
#######################


clear
sed -n '2,7s/#//p' "$0"
echo " Skynet Lite by Willem Bartels"
echo " Code based on Skynet By Adamm"
echo


if [ "$command" = "reset" ] || ! ipset list -n Skynet-Master >/dev/null 2>&1; then
		logger -st Skynet "[i] Install"
		touch "$file_installtime"
		touch "$file_errorlog"
		echo 0 > "$file_updatecount"
		if [ "$0" != "/jffs/scripts/firewall" ]; then
			mv -f "$0" "/jffs/scripts/firewall"
			logger -st Skynet "[*] Skynet Lite moved to /jffs/scripts/firewall"
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
		Unload_IPTables
		Unload_LogIPTables
		Unload_IPSets
		echo 'create Skynet-Master list:set size 64 comment counters
		create Skynet-Whitelist hash:net hashsize 64 comment
		create Skynet-Blacklist hash:net hashsize 64 comment
		create Skynet-Domain hash:net hashsize 64 comment
		create Skynet-ASN hash:net hashsize 64 comment
		add Skynet-Master Skynet-Blacklist comment "blacklist_ip/cidr"
		add Skynet-Master Skynet-Domain comment "blacklist_domain"
		add Skynet-Master Skynet-ASN comment "blacklist_asn"' | tr -d '\t' | ipset restore -!
		Load_IPTables
		Load_LogIPTables
		command="update"
fi


ip=$(echo "$command" | Is_IP) || ip="noip"
case "$command" in
		"uninstall")
			logger -st Skynet "[*] Uninstall Skynet Lite"
			if [ -f "/jffs/scripts/firewall-start" ]; then
				chmod 755 "/jffs/scripts/firewall-start"
				config=$(grep -v "/jffs/scripts/firewall" "/jffs/scripts/firewall-start")
				echo "$config" > "/jffs/scripts/firewall-start"
			fi
			cru d Skynet_update
			Unload_IPTables
			Unload_LogIPTables
			Unload_IPSets
			rm -fr "$dir_skynet"
			rm -f "$lockfile" "$0"
			echo; exit 0;
		;;


		"error")
			if [ -f "$file_errorlog" ] && [ $(wc -l < "$file_errorlog") -ge 1 ]; then
				cat "$file_errorlog"
			else
				echo "Empty error log"
			fi
			echo; exit 0;
		;;


		"update")
			echo "-----------------------------------------------------------"
			echo " Update                                                    "
			echo "-----------------------------------------------------------"
			if [ "$option" = "cru" ]; then
				updatecount=$(head -1 "$file_updatecount" 2>/dev/null)
				updatecount=$((updatecount + 1))
				echo "$updatecount" > "$file_updatecount"
			fi
			Load_Whitelist
			Load_Blacklist
			Load_Domain
			Load_ASN
			Download_Set
		;;


		"fresh")
			echo "-----------------------------------------------------------"
			echo " Blacklist                                   Last download "
			echo "-----------------------------------------------------------"
			lookup=$(ipset list Skynet-Master | Filter_Skynet_Set | tr -d '"' | awk '{print $1, $7}')
			cd "$dir_cache"
			for setname in $(ls -1t | Filter_Skynet_Set); do
				printf " %-40s  %15s\n" "$(echo "$lookup" | awk -v setname="$setname" '$1 == setname {print $2}')" "$(File_Age "$dir_cache/$setname")"
			done
		;;


		"$ip")
			echo "-----------------------------------------------------------"
			echo " Search for $ip"
			echo "-----------------------------------------------------------"
			if ipset -q test "Skynet-Whitelist" "$ip"; then
				echo " [*] whitelist"
			else
				echo " [ ] whitelist"
			fi
			lookup=$(ipset list Skynet-Master | Filter_Skynet | tr -d '"' | awk '{print $1, $7}')
			for setname in $(echo "$lookup" | sort -k2 | awk '{print $1}'); do
				if ipset -q test "$setname" "$ip"; then
					echo " [*] $(echo "$lookup" | awk -v setname="$setname" '$1 == setname {print $2}')"
				else
					echo " [ ] $(echo "$lookup" | awk -v setname="$setname" '$1 == setname {print $2}')"
				fi
			done
		;;


		*)
			echo "-----------------------------------------------------------"
			echo " Blacklist                                         Blocked "
			echo "-----------------------------------------------------------"
			ipset list Skynet-Master | Filter_Skynet | tr -d '"' | sort -k3,3gr -k7,7 | awk '{printf " %-40s  %15s\n", $7, $3}'
		;;
esac


echo "-----------------------------------------------------------"
printf " %-25s  %30s\n\n" "Uptime $(File_Age "$file_installtime")" "$(if [ $(ls -1 "$dir_retry" | Filter_Skynet_Set | wc -l) -ge 1 ] || [ -f "$file_retryasn" ]; then echo "[i] Failed downloads queued"; fi)"
