# Skynet Lite - Firewall & Security Enhancements

Lightweight firewall addition for ARM/HND based ASUS Routers using IPSet.
Skynet Lite relies on the IPTables from Skynet by Adamm.

## Some key features
- Small one file shell script (also uses tmp directory).
- No need for an external USB drive.
- Only updates new or changed ipsets.
- To prevent downtime use the ipset swap feature.

## Installation
Ensure you have an [Asuswrt-Merlin](https://www.asuswrt-merlin.net/) firmware and enabled the JFFS2 partition:
```
Administration > System > Enable JFFS custom scripts and configs: Yes > Apply
```

Type the following line in your favorite SSH Client:

```Shell
curl https://raw.githubusercontent.com/wbartels/IPSet_ASUS_Lite/master/firewall.sh --output /jffs/scripts/firewall && chmod 755 /jffs/scripts/firewall && sh /jffs/scripts/firewall
```

## Uninstall

Type the following line in your favorite SSH Client:

```Shell
sh /jffs/scripts/firewall uninstall
```

## Commands

```
firewall
firewall 1.1.1.1
firewall fresh
firewall frequency
firewall entries
firewall warning
firewall error
firewall update
firewall reset
firewall uninstall
firewall help
```

To make the commands above available form all directories, type the following line in your favorite SSH Client:

```Shell
echo 'export PATH=$PATH:/jffs/scripts' >> '/jffs/configs/profile.add'
```

### Donate to Skynet by Adamm

This script will always be open source and free to use, but if you want to support future development you can do so by [Donating With PayPal.](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=BPN4LTRZKDTML)

### About

> Skynet gained self-awareness after it had spread into millions of computer servers all across the world; realizing the extent of its abilities, its creators tried to deactivate it. In the interest of self-preservation, Skynet concluded that all of humanity would attempt to destroy it and impede its capability in safeguarding the world. Its operations are almost exclusively performed by servers, mobile devices, drones, military satellites, war-machines, androids and cyborgs (usually a terminator), and other computer systems. As a programming directive, Skynet's manifestation is that of an overarching, global, artificial intelligence hierarchy (AI takeover), which seeks to exterminate the human race in order to fulfill the mandates of its original coding. (▀̿Ĺ̯▀̿ ̿)
