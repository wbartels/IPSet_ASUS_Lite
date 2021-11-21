# Skynet Lite - Firewall & Security Enhancements

Lightweight firewall addition for ARM/HND based ASUS Routers using IPSet.
Skynet Lite relies on the IPTables from Skynet by Adamm.

I started this proof of concept for my own use and to demonstrate two new features:
- Only update new or changed ipsets.
- Use the ipset swap feature.

But I couldn't stop when I learned programming in shell script.
The main focus of this project is the update process.

## Key features
- Small one file shell script, no need for an external USB drive.
- Support for plain text gzip transfer-encoding.
- Only download and update changed blocklist sets.
- Use incremental update for all blocklist sets.
- For all other lists the ipset swap feature is used.

## Installation
Ensure you have an [Asuswrt-Merlin](https://www.asuswrt-merlin.net/) firmware and enabled the JFFS2 partition:
```
Administration > System > Enable JFFS custom scripts and configs: Yes > Apply
```

Type the following line in your favorite SSH Client:

```Shell
curl https://raw.githubusercontent.com/wbartels/IPSet_ASUS_Lite/master/firewall.sh --output /jffs/scripts/firewall && chmod 755 /jffs/scripts/firewall && /jffs/scripts/firewall
```

## Uninstall

Type the following line in your favorite SSH Client:

```Shell
/jffs/scripts/firewall uninstall
```

## Commands

```
firewall
firewall 8.8.8.8
firewall dns.google
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

To make the commands above available from all directories, type the following line in your favorite SSH Client:

```Shell
echo 'export PATH=$PATH:/jffs/scripts' >> '/jffs/configs/profile.add'
```

### Donate to Skynet by Adamm

This script will always be open source and free to use, but if you want to support future development you can do so by [Donating With PayPal.](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=BPN4LTRZKDTML)
