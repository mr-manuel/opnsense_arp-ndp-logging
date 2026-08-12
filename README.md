# ARP/NDP Logging - arpwatch alternative for OPNsense

<small>GitHub repository: [mr-manuel/opnsense_arp-ndp-logging](https://github.com/mr-manuel/opnsense_arp-ndp-logging)</small>


## Disclaimer

I wrote this plugin for myself. I'm not responsible, if you damage something using it.


## Supporting/Sponsoring this project

You like the project and you want to support me?

[<img src="https://github.md0.eu/uploads/donate-button.svg" height="50">](https://www.paypal.com/donate/?hosted_button_id=3NEVZBDM5KABW)


## Purpose

ARP/NDP Logging is a versatile network monitoring tool that tracks and logs changes in
ARP (Address Resolution Protocol) and NDP (Neighbor Discovery Protocol) tables, capturing
key details such as IPv4 and IPv6 addresses, hostnames, MAC addresses, and interface
changes. The plugin is configurable, allowing administrators to selectively enable or
disable tracking for different modifications based on specific needs, whether it's for IP
address shifts, hostname updates, new MAC detections, or interface changes. This
customization and comprehensive logging ensure precise, up-to-date network visibility,
ideal for securing networks and managing dynamic device inventories effectively.

This was originally developed for submission to the official
[opnsense/plugins](https://github.com/opnsense/plugins) repository, but will not be
merged upstream. It is published here so it can still be installed manually.

## Install

Will be added shortly after the tests ended.

## Config

Go to `Services` -> `ARP/NDP Logging` -> `General` and configure the plugin:

- **Enable**: Turn the logging service on or off.
- **Protocols**: Track IPv4 and IPv6, IPv4 only, or IPv6 only.
- **Interfaces**: Restrict tracking to specific interfaces (default: all).
- **Suppress MAC addresses**: A list of MAC addresses to exclude from logging.
- **Ignore case**: Compare MAC, IPv6, and hostname values case-insensitively.
- **Log new entries / MAC changes / IPv4 changes / IPv6 changes / hostname changes /
  interface changes**: Toggle which kinds of changes get logged.
- **Retention (days)**: How long log entries are kept (1-365 days, default: 30).
