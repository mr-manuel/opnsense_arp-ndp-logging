#!/usr/local/bin/python3

"""

Copyright (C) 2025 github.com/mr-manuel
All rights reserved.

License: BSD 2-Clause

"""


import argparse
import csv
import html
import json
import logging
import os
import shutil
import smtplib
import socket
import sqlite3
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import configparser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr
from io import StringIO
from datetime import datetime


CONFIG_FILE = "/usr/local/etc/arpndplogging.conf"
CONFIG_XML_FILE = "/conf/config.xml"
DB_FILE = "/var/db/arpndplogging/arpndplogging.db"
LOG_FILE = "/var/log/arpndplogging.log"
MAC_VENDOR_FILE = "/var/db/arpndplogging/oui.csv"

# Create directories
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)


# Set up logging to match RFC 5424
class CustomLogRecord(logging.LogRecord):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hostname = socket.gethostname()
        self.appname = "arpndplogging"
        self.procid = os.getpid()


logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="<134>1 %(asctime)s %(hostname)s %(appname)s %(procid)s - [meta] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)


# Add hostname, appname, procid to the log records
logging.Formatter.converter = time.localtime  # Use local time
logging.Formatter.default_msec_format = "%s.%03d"

logging.setLogRecordFactory(CustomLogRecord)

# Create database
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS arp_entries (
        mac TEXT,
        ipv4 TEXT,
        ipv6 TEXT,
        interface TEXT,
        hostname TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """
)
cursor.execute("CREATE INDEX IF NOT EXISTS idx_arp_entries_mac ON arp_entries (mac)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_arp_entries_ipv4 ON arp_entries (ipv4)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_arp_entries_ipv6 ON arp_entries (ipv6)")
cursor.execute(
    "CREATE INDEX IF NOT EXISTS idx_arp_entries_timestamp ON arp_entries (timestamp)"
)

# Create events table (append-only log of new entries/changes, used by the
# dashboard widget to show recent activity - arp_entries only holds current
# state per MAC and its timestamp is bumped on every poll, changed or not,
# so it can't answer "what changed recently" on its own)
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS events (
        mac TEXT,
        ipv4 TEXT,
        ipv6 TEXT,
        interface TEXT,
        hostname TEXT,
        vendor TEXT,
        event_type TEXT,
        message TEXT,
        changes TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """
)
cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp)")

# Migrate an events table created before the "vendor"/"changes" columns
# existed (CREATE TABLE IF NOT EXISTS above won't add them to an
# already-existing table)
cursor.execute("PRAGMA table_info(events)")
_events_columns = {row[1] for row in cursor.fetchall()}
for _column in ("vendor", "changes"):
    if _column not in _events_columns:
        cursor.execute(f"ALTER TABLE events ADD COLUMN {_column} TEXT")


# Read configuration file
config = configparser.ConfigParser(interpolation=None)
with open(CONFIG_FILE) as f:
    config.read_file(StringIO("[default]\n" + f.read()))

try:
    protocols = config["default"].get("protocols", fallback="all")
    interfaces = (
        config["default"].get("interfaces").replace("_", ".").split(" ")
        if config["default"].get("interfaces") is not None
        else []
    )
    suppress_mac = (
        config["default"].get("suppress_mac").split(" ")
        if config["default"].get("suppress_mac") is not None
        else []
    )
    ignore_case = config["default"].getboolean("ignore_case", fallback=False)
    log_new_entries = config["default"].getboolean("log_new_entries", fallback=True)
    log_mac_changes = config["default"].getboolean("log_mac_changes", fallback=True)
    log_ipv4_changes = config["default"].getboolean("log_ipv4_changes", fallback=False)
    log_ipv6_changes = config["default"].getboolean("log_ipv6_changes", fallback=False)
    log_hostname_changes = config["default"].getboolean(
        "log_hostname_changes", fallback=False
    )
    log_interface_changes = config["default"].getboolean(
        "log_interface_changes", fallback=False
    )
    retention_days = config["default"].getint("retention_days", fallback=30)

    mail_enabled = config["default"].getboolean("mail_enabled", fallback=False)
    mail_smtp_host = config["default"].get("mail_smtp_host", fallback="")
    mail_smtp_port = config["default"].getint("mail_smtp_port", fallback=587)
    mail_encryption = config["default"].get("mail_encryption", fallback="starttls")
    mail_smtp_username = config["default"].get("mail_smtp_username", fallback="")
    mail_smtp_password = config["default"].get("mail_smtp_password", fallback="")
    mail_from = config["default"].get("mail_from", fallback="")
    mail_to = (
        config["default"].get("mail_to").split(" ")
        if config["default"].get("mail_to") is not None
        else []
    )

    webhook_enabled = config["default"].getboolean("webhook_enabled", fallback=False)
    webhook_url = config["default"].get("webhook_url", fallback="")
    webhook_method = config["default"].get("webhook_method", fallback="POST").upper()
except (configparser.Error, ValueError) as e:
    logging.error(f"Invalid configuration in {CONFIG_FILE}: {e}")
    raise SystemExit(1)

# add firewall MAC addresses to suppress_mac
device_mac_addresses = (
    subprocess.run(
        "ifconfig -a | grep ether  | awk '{print $2}' | sort | uniq",
        shell=True,
        capture_output=True,
        text=True,
    )
    .stdout.strip()
    .split("\n")
)

suppress_mac.extend(device_mac_addresses)

# suppress_mac is always matched case-insensitively
suppress_mac = [mac.lower() for mac in suppress_mac]


def resolve_hostname(ip):
    # Reverse DNS lookup via the system resolver (no subprocess/shell involved)
    if ip == "unknown":
        return []
    try:
        name, aliases, _ = socket.gethostbyaddr(ip)
        return [n.rstrip(".") for n in [name] + aliases]
    except OSError:
        return []


_hostname_sources_cache = None
_hostname_sources_cache_mtime = None


def _load_hostname_sources():
    # Reload only when config.xml actually changed, same caching approach as
    # _get_mac_vendor_cache() below
    global _hostname_sources_cache, _hostname_sources_cache_mtime

    try:
        mtime = os.path.getmtime(CONFIG_XML_FILE)
    except OSError:
        return {}, {}

    if _hostname_sources_cache is not None and _hostname_sources_cache_mtime == mtime:
        return _hostname_sources_cache

    dnsmasq_map = {}
    dhcp_map = {}
    try:
        # config.xml is OPNsense's own trusted, root-owned system config (not
        # attacker-supplied input), so the stdlib parser's XXE/entity-expansion
        # exposure doesn't apply here; avoids adding a defusedxml pkg
        # dependency for a plugin that otherwise only needs the base system
        root = ET.parse(CONFIG_XML_FILE).getroot()

        # Dnsmasq host overrides
        for host in root.findall("./OPNsense/Dnsmasq/hosts/*"):
            hwaddr = (host.findtext("hwaddr") or "").strip()
            hostname = (host.findtext("host") or "").strip()
            domain = (host.findtext("domain") or "").strip()
            if not hwaddr or not hostname:
                continue
            fqdn = f"{hostname}.{domain}" if domain else hostname
            for mac in hwaddr.split(","):
                mac = mac.strip().lower()
                if mac:
                    dnsmasq_map[mac] = fqdn

        # ISC DHCP static mappings (enabled interfaces only)
        for ifcfg in root.findall("./dhcpd/*"):
            if ifcfg.find("enable") is None:
                continue
            for staticmap in ifcfg.findall("./staticmap"):
                mac = (staticmap.findtext("mac") or "").strip().lower()
                name = (staticmap.findtext("hostname") or "").strip() or (
                    staticmap.findtext("descr") or ""
                ).strip()
                if mac and name and mac not in dhcp_map:
                    dhcp_map[mac] = name
    except (ET.ParseError, OSError) as e:
        logging.warning(f"Failed to parse {CONFIG_XML_FILE} for hostname sources: {e}")
        dnsmasq_map, dhcp_map = {}, {}

    _hostname_sources_cache = (dnsmasq_map, dhcp_map)
    _hostname_sources_cache_mtime = mtime
    return _hostname_sources_cache


def lookup_configured_hostname(mac):
    # Dnsmasq host overrides take priority over ISC DHCP static mappings
    dnsmasq_map, dhcp_map = _load_hostname_sources()
    mac = mac.lower()
    return dnsmasq_map.get(mac) or dhcp_map.get(mac)


_MAIL_EVENT_LABELS = {
    "mac_change": "MAC",
    "ipv4_change": "IPv4",
    "ipv6_change": "IPv6",
    "hostname_change": "Hostname",
    "interface_change": "Interface",
}

_MAIL_DETAIL_ROWS = (
    ("MAC", "mac"),
    ("Vendor", "vendor"),
    ("Hostname", "hostname"),
    ("IPv4", "ipv4"),
    ("IPv6", "ipv6"),
    ("Interface", "interface"),
    ("Time", "timestamp"),
)


def _humanize_event_type(event_type):
    if event_type == "new_entry":
        return "New device detected"
    if event_type == "test":
        return "Test notification"
    parts = [_MAIL_EVENT_LABELS.get(tag, tag) for tag in event_type.split(",")]
    return "Changed: " + ", ".join(parts)


def _build_mail_text(event):
    changes = event.get("changes", {})
    lines = [_humanize_event_type(event["event_type"]), ""]
    for label, key in _MAIL_DETAIL_ROWS:
        if key in changes:
            lines.append(f"{label}: {changes[key]} -> {event[key]}")
        else:
            lines.append(f"{label}: {event[key]}")
    lines.append("")
    lines.append(event["message"])
    return "\n".join(lines)


def _build_mail_html(event):
    def esc(value):
        return html.escape(str(value))

    def value_cell(key):
        changes = event.get("changes", {})
        if key not in changes:
            return esc(event[key])
        return (
            '<s style="color:#c0392b;">' + esc(changes[key]) + '</s>'
            ' &rarr; '
            '<span style="color:#1e8449; font-weight:600;">' + esc(event[key]) + '</span>'
        )

    rows = "".join(
        '<tr>'
        '<td style="padding:6px 0; color:#8a8a8e; width:110px; vertical-align:top; '
        'font-size:14px; font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,'
        'Helvetica,Arial,sans-serif;">' + esc(label) + '</td>'
        '<td style="padding:6px 0; color:#1a1a1a; vertical-align:top; font-size:14px; '
        'font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Helvetica,Arial,'
        'sans-serif;">' + value_cell(key) + '</td>'
        '</tr>'
        for label, key in _MAIL_DETAIL_ROWS
    )

    return (
        '<!DOCTYPE html>'
        '<html><body style="margin:0; padding:0; background-color:#f4f4f7;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="background-color:#f4f4f7; padding:24px 0;"><tr><td align="center">'
        '<table role="presentation" width="600" cellpadding="0" cellspacing="0" '
        'style="max-width:600px; width:100%; background-color:#ffffff; border-radius:8px; '
        'overflow:hidden; border:1px solid #e2e2e7;">'
        '<tr><td style="background-color:#2c3e50; padding:20px 24px;">'
        '<span style="color:#ffffff; font-size:18px; font-weight:600; '
        'font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Helvetica,Arial,'
        'sans-serif;">ARP/NDP Logging</span>'
        '</td></tr>'
        '<tr><td style="padding:24px;">'
        '<p style="margin:0 0 16px 0; font-size:16px; color:#1a1a1a; font-weight:600; '
        'font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Helvetica,Arial,'
        'sans-serif;">' + esc(_humanize_event_type(event["event_type"])) + '</p>'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
        + rows +
        '</table>'
        '</td></tr>'
        '<tr><td style="padding:0 24px 24px 24px;">'
        '<div style="background-color:#f4f4f7; border-radius:6px; padding:12px 16px; '
        'font-family:ui-monospace,Consolas,Menlo,monospace; font-size:12px; color:#555555; '
        'word-break:break-word;">' + esc(event["message"]) + '</div>'
        '</td></tr>'
        '<tr><td style="padding:16px 24px; border-top:1px solid #e2e2e7;">'
        '<span style="font-size:12px; color:#8a8a8e; '
        'font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,Helvetica,Arial,'
        'sans-serif;">Sent by the ARP/NDP Logging OPNsense plugin</span>'
        '</td></tr>'
        '</table>'
        '</td></tr></table>'
        '</body></html>'
    )


def send_mail(event):
    if not mail_enabled:
        return False, "Mail notifications are disabled"
    if not mail_smtp_host or not mail_from or not mail_to:
        return False, "Mail notifications are not fully configured"
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"ARP/NDP Logging: {_humanize_event_type(event['event_type'])}"
        msg["From"] = formataddr((socket.gethostname(), mail_from))
        msg["To"] = ", ".join(mail_to)
        msg.attach(MIMEText(_build_mail_text(event), "plain"))
        msg.attach(MIMEText(_build_mail_html(event), "html"))

        if mail_encryption == "ssl":
            server = smtplib.SMTP_SSL(mail_smtp_host, mail_smtp_port, timeout=10)
        else:
            server = smtplib.SMTP(mail_smtp_host, mail_smtp_port, timeout=10)
        try:
            if mail_encryption == "starttls":
                server.starttls()
            if mail_smtp_username and mail_smtp_password:
                server.login(mail_smtp_username, mail_smtp_password)
            server.sendmail(mail_from, mail_to, msg.as_string())
        finally:
            server.quit()
        return True, None
    except Exception as e:
        logging.warning(f"Failed to send mail notification: {e}")
        return False, str(e)


def send_webhook(event):
    if not webhook_enabled:
        return False, "Webhook notifications are disabled"
    if not webhook_url:
        return False, "Webhook URL is not configured"
    try:
        if webhook_method == "GET":
            separator = "&" if "?" in webhook_url else "?"
            url = webhook_url + separator + urllib.parse.urlencode(event)
            req = urllib.request.Request(url, method="GET")
        else:
            data = json.dumps(event).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
        with urllib.request.urlopen(req, timeout=10) as response:
            response.read()
        return True, None
    except Exception as e:
        logging.warning(f"Failed to send webhook notification: {e}")
        return False, str(e)


def emit_event(
    event_type, mac, ipv4, ipv6, hostname, interface, timestamp, message, changes=None
):
    logging.info(message)

    changes = changes or {}
    vendor = mac_vendor_check(mac)
    cursor.execute(
        "INSERT INTO events (mac, ipv4, ipv6, interface, hostname, vendor, event_type, message, changes, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (mac, ipv4, ipv6, interface, hostname, vendor, event_type, message, json.dumps(changes), timestamp),
    )

    if mail_enabled or webhook_enabled:
        event = {
            "event_type": event_type,
            "mac": mac,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "hostname": hostname,
            "vendor": vendor,
            "interface": interface,
            "timestamp": timestamp,
            "message": message,
            # old values for whichever fields changed, e.g. {"ipv4": "1.2.3.3"} -
            # lets the mail template show an old -> new diff per field
            "changes": changes,
        }
        if mail_enabled:
            send_mail(event)
        if webhook_enabled:
            send_webhook(event)


def main():
    while True:
        time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # create a dictionary with the current entries
        current_entries_dict = {}

        # Check ARP table
        if protocols == "all" or protocols == "ipv4_only":
            # $2 = IPv4, $4 = MAC, $6 = Interface
            filter = ' | grep -v \'incomplete\' | awk \'{gsub(/[()]/, "", $2); print $2 " " $4 " " $6}\''
            if len(interfaces) == 0:
                result = subprocess.run(
                    "arp -an" + filter,
                    shell=True,
                    capture_output=True,
                    text=True,
                )
                current_ipv4_entries = result.stdout.strip().split("\n")
            else:
                current_ipv4_entries = []
                for interface in interfaces:
                    result = subprocess.run(
                        "arp -i " + interface + " -an" + filter,
                        shell=True,
                        capture_output=True,
                        text=True,
                    )
                    current_ipv4_entries.extend(result.stdout.strip().split("\n"))

            # Filter out empty strings
            current_ipv4_entries = [
                entries for entries in current_ipv4_entries if entries
            ]

            # populate the current_entries_dict
            if len(current_ipv4_entries) > 0:
                for entry in current_ipv4_entries:
                    ipv4, mac, interface = entry.split()
                    if ignore_case:
                        mac = mac.lower()
                    current_entries_dict[mac] = {
                        "ipv4": ipv4,
                        "ipv6": "unknown",
                        "interface": interface,
                    }

        # Check NDP table
        if protocols == "all" or protocols == "ipv6_only":
            # $1 = IPv6, $2 = MAC, $3 = Interface
            filter = ' | grep -v "incomplete" | grep -v "Neighbor" | awk \'{gsub(/%.*/, "", $1); print $1 " " $2 " " $3}\''
            if len(interfaces) == 0:
                result = subprocess.run(
                    "ndp -an" + filter,
                    shell=True,
                    capture_output=True,
                    text=True,
                )
                current_ipv6_entries = result.stdout.strip().split("\n")
            else:
                current_ipv6_entries = []
                for interface in interfaces:
                    result = subprocess.run(
                        "ndp -an | grep " + interface + filter,
                        shell=True,
                        capture_output=True,
                        text=True,
                    )
                    current_ipv6_entries.extend(result.stdout.strip().split("\n"))

            # Filter out empty strings
            current_ipv6_entries = [
                entries for entries in current_ipv6_entries if entries
            ]

            # populate the current_entries_dict
            if len(current_ipv6_entries) > 0:
                for entry in current_ipv6_entries:
                    ipv6, mac, interface = entry.split()
                    if ignore_case:
                        ipv6 = ipv6.lower()
                        mac = mac.lower()
                    if mac in current_entries_dict:
                        current_entries_dict[mac]["ipv6"] = ipv6
                    else:
                        current_entries_dict[mac] = {
                            "ipv4": "unknown",
                            "ipv6": ipv6,
                            "interface": interface,
                        }

        # Delete expired ARP entries
        cursor.execute(
            f"DELETE FROM arp_entries WHERE timestamp < datetime('now', '-{retention_days} day')"
        )
        cursor.execute(
            f"DELETE FROM events WHERE timestamp < datetime('now', '-{retention_days} day')"
        )

        # Select all current ARP entries
        cursor.execute(
            "SELECT mac, ipv4, ipv6, interface, hostname, timestamp FROM arp_entries"
        )
        saved_ipv4_entries = set(cursor.fetchall())

        # Save entries in a dictionary with MAC as the key
        saved_entries_dict_by_mac = {
            entry[0]: {
                "ipv4": entry[1],
                "ipv6": entry[2],
                "interface": entry[3],
                "hostname": entry[4],
                "timestamp": entry[5],
            }
            for entry in saved_ipv4_entries
        }

        # Save entries in a dictionary with MAC as the key
        saved_ipv4_entries_dict_by_ip = {
            entry[1]: {
                "mac": entry[0],
                "interface": entry[3],
                "hostname": entry[4],
                "timestamp": entry[5],
            }
            for entry in saved_ipv4_entries
        }

        # Save entries in a dictionary with MAC as the key
        saved_ipv6_entries_dict_by_ip = {
            entry[2]: {
                "mac": entry[0],
                "interface": entry[3],
                "hostname": entry[4],
                "timestamp": entry[5],
            }
            for entry in saved_ipv4_entries
        }

        # check if current_ipv4_entries_dict is empty
        if len(current_entries_dict) > 0:
            for mac, entry in current_entries_dict.items():

                ipv4 = entry["ipv4"]
                ipv6 = entry["ipv6"]
                interface = entry["interface"]

                # A protocol's neighbor cache can expire faster than the other
                # (e.g. NDP vs ARP), which would otherwise make an already-known
                # address flap to "unknown" every time it isn't seen in a given
                # poll. Fall back to the last known value for a matched MAC so a
                # transient cache miss isn't logged/stored as a real change.
                if mac in saved_entries_dict_by_mac:
                    saved = saved_entries_dict_by_mac[mac]
                    if ipv4 == "unknown":
                        ipv4 = saved["ipv4"]
                    if ipv6 == "unknown":
                        ipv6 = saved["ipv6"]

                # Get hostname: Dnsmasq host overrides and ISC DHCP static
                # mappings are checked before falling back to reverse DNS,
                # since they're authoritative and don't depend on the device
                # actually registering a PTR record
                configured_hostname = lookup_configured_hostname(mac)
                if configured_hostname:
                    hostname = (
                        configured_hostname.lower()
                        if ignore_case
                        else configured_hostname
                    )
                else:
                    hostname = resolve_hostname(ipv4) + resolve_hostname(ipv6)
                    if ignore_case:
                        hostname = [name.lower() for name in hostname]

                    # Remove duplicates and sort the hostname list
                    hostname = sorted(set(hostname))
                    # Filter out empty strings
                    hostname = [name for name in hostname if name]

                    if not hostname:
                        hostname = "unknown"
                    else:
                        # split by newline, sort and join with ;
                        hostname = "; ".join(sorted(hostname))

                # Skip suppressed MAC addresses (always matched case-insensitively)
                if mac.lower() in suppress_mac:
                    continue

                # Check if the MAC entry already exists
                if mac in saved_entries_dict_by_mac:

                    changes = False
                    changes_message = []
                    event_tags = []
                    changed_fields = {}

                    # Check if the IPv4 address has changed
                    if (
                        (protocols == "all" or protocols == "ipv4_only")
                        and log_ipv4_changes
                        and ipv4 != saved_entries_dict_by_mac[mac]["ipv4"]
                    ):
                        changes = True
                        event_tags.append("ipv4_change")
                        changed_fields["ipv4"] = saved_entries_dict_by_mac[mac]["ipv4"]
                        changes_message.append(
                            f"OLD IPv4: {saved_entries_dict_by_mac[mac]['ipv4']}"
                        )

                    # Check if the IPv6 address has changed
                    if (
                        (protocols == "all" or protocols == "ipv6_only")
                        and log_ipv6_changes
                        and ipv6 != saved_entries_dict_by_mac[mac]["ipv6"]
                    ):
                        changes = True
                        event_tags.append("ipv6_change")
                        changed_fields["ipv6"] = saved_entries_dict_by_mac[mac]["ipv6"]
                        changes_message.append(
                            f"OLD IPv6: {saved_entries_dict_by_mac[mac]['ipv6']}"
                        )

                    # Check if the hostname has changed
                    if (
                        log_hostname_changes
                        and hostname != saved_entries_dict_by_mac[mac]["hostname"]
                    ):
                        changes = True
                        event_tags.append("hostname_change")
                        changed_fields["hostname"] = saved_entries_dict_by_mac[mac]["hostname"]
                        changes_message.append(
                            f"OLD Hostname: {saved_entries_dict_by_mac[mac]['hostname']}"
                        )

                    # Check if the interface has changed
                    if (
                        log_interface_changes
                        and interface != saved_entries_dict_by_mac[mac]["interface"]
                    ):
                        changes = True
                        event_tags.append("interface_change")
                        changed_fields["interface"] = saved_entries_dict_by_mac[mac]["interface"]
                        changes_message.append(
                            f"OLD Interface: {saved_entries_dict_by_mac[mac]['interface']}"
                        )

                    # Update the entry
                    if changes:
                        cursor.execute(
                            "UPDATE arp_entries SET ipv4 = ?, ipv6 = ?, interface = ?, hostname = ?, timestamp = ? WHERE mac = ?",
                            (ipv4, ipv6, interface, hostname, time_now, mac),
                        )
                        message = (
                            "ARP - Changes detected! "
                            + (
                                f"IPv4: {ipv4} | "
                                if protocols == "all" or protocols == "ipv4_only"
                                else ""
                            )
                            + (
                                f"IPv6: {ipv6} | "
                                if protocols == "all" or protocols == "ipv6_only"
                                else ""
                            )
                            + f"Hostname: {hostname} | MAC: {mac} | Vendor: {mac_vendor_check(mac)} | Interface: {interface}"
                            + (
                                " | " + " | ".join(changes_message)
                                if len(changes_message) > 0
                                else ""
                            )
                        )
                        emit_event(
                            ",".join(event_tags),
                            mac,
                            ipv4,
                            ipv6,
                            hostname,
                            interface,
                            time_now,
                            message,
                            changed_fields,
                        )
                    # Update the timestamp
                    else:
                        cursor.execute(
                            "UPDATE arp_entries SET timestamp = ? WHERE ipv4 = ?",
                            (time_now, ipv4),
                        )

                # Check if the IPv4 entry already exists
                # This check allows to see, if an address is spoofed or multiple devices have the same IP
                elif ipv4 != "unknown" and ipv4 in saved_ipv4_entries_dict_by_ip:

                    changes = False
                    changes_message = []
                    event_tags = []
                    changed_fields = {}

                    # Check if the MAC address has changed
                    if (
                        log_mac_changes
                        and mac != saved_ipv4_entries_dict_by_ip[ipv4]["mac"]
                    ):
                        changes = True
                        event_tags.append("mac_change")
                        old_mac = saved_ipv4_entries_dict_by_ip[ipv4]["mac"]
                        changed_fields["mac"] = old_mac
                        changed_fields["vendor"] = mac_vendor_check(old_mac)
                        changes_message.append(
                            f"OLD MAC: {old_mac} | OLD vendor: {changed_fields['vendor']}"
                        )

                    # Check if the hostname has changed
                    if (
                        log_hostname_changes
                        and hostname != saved_ipv4_entries_dict_by_ip[ipv4]["hostname"]
                    ):
                        changes = True
                        event_tags.append("hostname_change")
                        changed_fields["hostname"] = saved_ipv4_entries_dict_by_ip[ipv4]["hostname"]
                        changes_message.append(
                            f"OLD Hostname: {saved_ipv4_entries_dict_by_ip[ipv4]['hostname']}"
                        )

                    # Check if the interface has changed
                    if (
                        log_interface_changes
                        and interface
                        != saved_ipv4_entries_dict_by_ip[ipv4]["interface"]
                    ):
                        changes = True
                        event_tags.append("interface_change")
                        changed_fields["interface"] = saved_ipv4_entries_dict_by_ip[ipv4]["interface"]
                        changes_message.append(
                            f"OLD Interface: {saved_ipv4_entries_dict_by_ip[ipv4]['interface']}"
                        )

                    # Update the entry
                    if changes:
                        cursor.execute(
                            "UPDATE arp_entries SET mac = ?, ipv6 = ?, interface = ?, hostname = ?, timestamp = ? WHERE ipv4 = ?",
                            (mac, ipv6, interface, hostname, time_now, ipv4),
                        )
                        message = (
                            "ARP - Changes detected! "
                            + (
                                f"IPv4: {ipv4} | "
                                if protocols == "all" or protocols == "ipv4_only"
                                else ""
                            )
                            + (
                                f"IPv6: {ipv6} | "
                                if protocols == "all" or protocols == "ipv6_only"
                                else ""
                            )
                            + f"Hostname: {hostname} | MAC: {mac} | Vendor: {mac_vendor_check(mac)} | Interface: {interface}"
                            + (
                                " | " + " | ".join(changes_message)
                                if len(changes_message) > 0
                                else ""
                            )
                        )
                        emit_event(
                            ",".join(event_tags),
                            mac,
                            ipv4,
                            ipv6,
                            hostname,
                            interface,
                            time_now,
                            message,
                            changed_fields,
                        )
                    # Update the timestamp
                    else:
                        cursor.execute(
                            "UPDATE arp_entries SET timestamp = ? WHERE ipv4 = ?",
                            (time_now, ipv4),
                        )

                # Check if the IPv6 entry already exists
                # This check allows to see, if an address is spoofed or multiple devices have the same IP
                elif ipv6 != "unknown" and ipv6 in saved_ipv6_entries_dict_by_ip:

                    changes = False
                    changes_message = []
                    event_tags = []
                    changed_fields = {}

                    # Check if the MAC address has changed
                    if (
                        log_mac_changes
                        and mac != saved_ipv6_entries_dict_by_ip[ipv6]["mac"]
                    ):
                        changes = True
                        event_tags.append("mac_change")
                        old_mac = saved_ipv6_entries_dict_by_ip[ipv6]["mac"]
                        changed_fields["mac"] = old_mac
                        changed_fields["vendor"] = mac_vendor_check(old_mac)
                        changes_message.append(
                            f"OLD MAC: {old_mac} | OLD vendor: {changed_fields['vendor']}"
                        )

                    # Check if the hostname has changed
                    if (
                        log_hostname_changes
                        and hostname != saved_ipv6_entries_dict_by_ip[ipv6]["hostname"]
                    ):
                        changes = True
                        event_tags.append("hostname_change")
                        changed_fields["hostname"] = saved_ipv6_entries_dict_by_ip[ipv6]["hostname"]
                        changes_message.append(
                            f"OLD Hostname: {saved_ipv6_entries_dict_by_ip[ipv6]['hostname']}"
                        )

                    # Check if the interface has changed
                    if (
                        log_interface_changes
                        and interface
                        != saved_ipv6_entries_dict_by_ip[ipv6]["interface"]
                    ):
                        changes = True
                        event_tags.append("interface_change")
                        changed_fields["interface"] = saved_ipv6_entries_dict_by_ip[ipv6]["interface"]
                        changes_message.append(
                            f"OLD Interface: {saved_ipv6_entries_dict_by_ip[ipv6]['interface']}"
                        )

                    # Update the entry
                    if changes:
                        cursor.execute(
                            "UPDATE arp_entries SET mac = ?, ipv4 = ?, interface = ?, hostname = ?, timestamp = ? WHERE ipv6 = ?",
                            (mac, ipv4, interface, hostname, time_now, ipv6),
                        )
                        message = (
                            "ARP - Changes detected! "
                            + (
                                f"IPv4: {ipv4} | "
                                if protocols == "all" or protocols == "ipv4_only"
                                else ""
                            )
                            + (
                                f"IPv6: {ipv6} | "
                                if protocols == "all" or protocols == "ipv6_only"
                                else ""
                            )
                            + f"Hostname: {hostname} | MAC: {mac} | Vendor: {mac_vendor_check(mac)} | Interface: {interface}"
                            + (
                                " | " + " | ".join(changes_message)
                                if len(changes_message) > 0
                                else ""
                            )
                        )
                        emit_event(
                            ",".join(event_tags),
                            mac,
                            ipv4,
                            ipv6,
                            hostname,
                            interface,
                            time_now,
                            message,
                            changed_fields,
                        )
                    # Update the timestamp
                    else:
                        cursor.execute(
                            "UPDATE arp_entries SET timestamp = ? WHERE ipv6 = ?",
                            (time_now, ipv6),
                        )

                elif log_new_entries:
                    message = (
                        "ARP - New entry detected! "
                        + (
                            f"IPv4: {ipv4} | "
                            if protocols == "all" or protocols == "ipv4_only"
                            else ""
                        )
                        + (
                            f"IPv6: {ipv6} | "
                            if protocols == "all" or protocols == "ipv6_only"
                            else ""
                        )
                        + f"Hostname: {hostname} | MAC: {mac} | Vendor: {mac_vendor_check(mac)} | Interface: {interface}"
                    )
                    cursor.execute(
                        "INSERT INTO arp_entries (mac, ipv4, ipv6, interface, hostname, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                        (mac, ipv4, ipv6, interface, hostname, time_now),
                    )
                    emit_event(
                        "new_entry",
                        mac,
                        ipv4,
                        ipv6,
                        hostname,
                        interface,
                        time_now,
                        message,
                    )

        conn.commit()

        # check if the log need to be rotated
        rotate_log()

        # Wait before next check
        time.sleep(60)


LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3


def rotate_log():
    # Rotate log file if necessary, keeping up to LOG_BACKUP_COUNT generations
    if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) <= LOG_MAX_BYTES:
        return

    oldest = f"{LOG_FILE}.{LOG_BACKUP_COUNT}"
    if os.path.exists(oldest):
        os.remove(oldest)
    for i in range(LOG_BACKUP_COUNT - 1, 0, -1):
        src = f"{LOG_FILE}.{i}"
        if os.path.exists(src):
            shutil.move(src, f"{LOG_FILE}.{i + 1}")
    shutil.move(LOG_FILE, f"{LOG_FILE}.1")
    open(LOG_FILE, "a").close()
    logging.info("Rotated log file")


def mac_vendor_list_download():
    # Download MAC address vendor list if older than 365 days
    if (
        not os.path.exists(MAC_VENDOR_FILE)
        or (time.time() - os.path.getmtime(MAC_VENDOR_FILE)) > 365 * 86400
    ):
        url = "https://maclookup.app/downloads/csv-database/get-db"
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                with open(MAC_VENDOR_FILE, "wb") as f:
                    f.write(response.read())
            logging.info("Downloaded MAC vendor list")
        except urllib.error.URLError as e:
            logging.error(f"Failed to download MAC vendor list: {e}")


_mac_vendor_cache = None
_mac_vendor_cache_mtime = None


def _get_mac_vendor_cache():
    # Reload the vendor list only when the file actually changed (e.g. after a
    # yearly re-download) instead of re-reading/re-parsing it on every lookup
    global _mac_vendor_cache, _mac_vendor_cache_mtime

    mtime = os.path.getmtime(MAC_VENDOR_FILE)
    if _mac_vendor_cache is not None and _mac_vendor_cache_mtime == mtime:
        return _mac_vendor_cache

    mac_vendor = {}
    with open(MAC_VENDOR_FILE, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                mac_prefix = row[0].strip().replace(":", "").lower()
                vendor = row[1].strip()
                mac_vendor[mac_prefix] = vendor

    _mac_vendor_cache = mac_vendor
    _mac_vendor_cache_mtime = mtime
    return _mac_vendor_cache


def mac_vendor_check(mac):
    mac_vendor = _get_mac_vendor_cache()

    # Search for the vendor by progressively increasing the length of the MAC prefix
    for length in range(6, 9):
        matches = [
            vendor
            for prefix, vendor in mac_vendor.items()
            if mac.replace(":", "").lower().startswith(prefix[:length])
        ]
        if len(matches) == 1:
            return matches[0]

    return "unknown"


def _test_event():
    return {
        "event_type": "test",
        "mac": "00:00:00:00:00:00",
        "ipv4": "unknown",
        "ipv6": "unknown",
        "hostname": "unknown",
        "vendor": "unknown",
        "interface": "unknown",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message": "This is a test event from the ARP/NDP Logging OPNsense plugin.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-mail", action="store_true")
    parser.add_argument("--test-webhook", action="store_true")
    args = parser.parse_args()

    if args.test_mail:
        ok, err = send_mail(_test_event())
        print("OK: test mail sent" if ok else f"FAILED: {err}")
        raise SystemExit(0 if ok else 1)

    if args.test_webhook:
        ok, err = send_webhook(_test_event())
        print("OK: test webhook sent" if ok else f"FAILED: {err}")
        raise SystemExit(0 if ok else 1)

    # check if the log need to be rotated
    rotate_log()

    logging.info("*** Starting ARP/NDP Logging ***")

    logging.info(f"protocols: {protocols}")
    logging.info(f"interfaces: {interfaces}")
    logging.info(f"suppress_mac: {suppress_mac}")
    logging.info(f"ignore_case: {ignore_case}")

    mac_vendor_list_download()

    main()
