# ARP/NDP Logging - arpwatch alternative for OPNsense

An OPNsense plugin for ARP and NDP logging: it watches the firewall's ARP (IPv4) and
NDP (IPv6 neighbor discovery) tables and logs new devices, MAC address changes, IP
address changes, hostname changes and interface changes - the same idea as `arpwatch`,
`arp-scan` or a DHCP lease log, but built directly into the OPNsense GUI as a proper
plugin with no external Monit/syslog setup required. Every logged device also gets its
manufacturer resolved from its MAC address (OUI/vendor lookup), so log entries and
change notifications are easier to identify at a glance. It can alert on the same
events by mail and/or webhook, prefers Dnsmasq host overrides and DHCP static
mappings over reverse DNS when resolving hostnames, and ships a Lobby dashboard
widget showing the device count and recent activity.

<small>GitHub repository: [mr-manuel/opnsense_arp-ndp-logging](https://github.com/mr-manuel/opnsense_arp-ndp-logging)</small>


## Disclaimer

I wrote this plugin for myself. I'm not responsible, if you damage something using it.


## Supporting/Sponsoring this project

You like the project and you want to support me?

[<img src="https://github.md0.eu/uploads/donate-button.svg" height="50">](https://www.paypal.com/donate/?hosted_button_id=3NEVZBDM5KABW)


## Purpose

The plugin is fully configurable: administrators can selectively enable or disable
logging for new devices, MAC address changes, IPv4/IPv6 address changes, hostname
changes and interface changes. That makes it useful both for simple network inventory
(what devices have ever been on my LAN) and for spotting suspicious activity such as
ARP spoofing, IP conflicts or a MAC address suddenly showing up on a different
interface.

This was originally developed for submission to the official
[opnsense/plugins](https://github.com/opnsense/plugins) repository, but will not be
merged upstream. It is instead published as its own `pkg` repository so it can be
installed and upgraded like any other OPNsense plugin.

## Install

One-time setup, done once via SSH/console on each firewall:

```
fetch -o /usr/local/etc/pkg/repos/mr-manuel_arp-ndp-logging.conf https://mr-manuel.github.io/opnsense_arp-ndp-logging/mr-manuel_arp-ndp-logging.conf
fetch -o /usr/local/etc/pkg/repos/mr-manuel_arp-ndp-logging.pub https://mr-manuel.github.io/opnsense_arp-ndp-logging/mr-manuel_arp-ndp-logging.pub
pkg update
```

After that, `ARP/NDP Logging` shows up under `System` -> `Firmware` -> `Plugins` like
any built-in plugin, and can be installed/upgraded/removed entirely from the GUI.

Releases are built and published automatically by
[GitHub Actions](.github/workflows/build.yml) whenever a `vX.Y.Z` tag is pushed.

## Config

Go to `Services` -> `ARP/NDP Logging` -> `General` and configure the plugin:

- **Enable**: Turn the logging service on or off.
- **Protocols**: Track IPv4 and IPv6, IPv4 only, or IPv6 only.
- **Interfaces**: Restrict tracking to specific interfaces (default: all).
- **Suppress MAC addresses**: A list of MAC addresses to exclude from logging (the
  firewall's own MAC addresses are always excluded automatically).
- **Ignore case**: Compare MAC, IPv6, and hostname values case-insensitively.
- **Log new entries / MAC changes / IPv4 changes / IPv6 changes / hostname changes /
  interface changes**: Toggle which kinds of changes get logged.
- **Retention (days)**: How long log entries are kept (1-365 days, default: 30).
- **Enable mail notifications**: Sends a mail for every event type enabled above.
  Configure the SMTP host/port/encryption, optional username/password, a From
  address and one or more To addresses. The **Send test mail** button saves the
  settings and reconfigures the service before sending, so it always reflects
  what's currently in the form.
- **Enable webhook notifications**: Sends a POST (JSON body) or GET (query string)
  request to a webhook URL for every event type enabled above. The payload/query
  fields are: `event_type`, `mac`, `ipv4`, `ipv6`, `hostname`, `vendor`, `interface`,
  `timestamp`, `message`. The **Send test webhook** button likewise saves and
  reconfigures first.

Use `Services` -> `ARP/NDP Logging` -> `Log File` to view the log directly in the GUI.
The service widget's **Reset Database** button stops the service, wipes its database
(so every device is logged as new again on the next scan) and restarts it.

## Hostname resolution

When resolving a device's hostname, the plugin checks these sources in order and
uses the first match:

1. Dnsmasq host overrides (`Services` -> `Dnsmasq DNS/DHCP` -> `Hosts`)
2. ISC DHCP static mappings on enabled interfaces (hostname field, falling back to
   the description)
3. Reverse DNS (PTR lookup) on the device's IPv4/IPv6 address

## Dashboard widget

A `ArpNdpLogging` widget is available on the Lobby dashboard, showing the total
number of tracked devices and the most recently added/changed devices. It shows an
error instead of the usual data if the service is not running.
