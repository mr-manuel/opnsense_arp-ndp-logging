#!/usr/local/bin/python3

"""

Copyright (C) 2025 github.com/mr-manuel
All rights reserved.

License: BSD 2-Clause

"""


import argparse
import csv
import html
import ipaddress
import json
import logging
import os
import queue
import shutil
import signal
import smtplib
import socket
import sqlite3
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import configparser
from email.charset import QP, Charset
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
TCPDUMP_BIN = "/usr/sbin/tcpdump"
TCPDUMP_SNAPLEN = 128

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
cursor.execute("DROP TABLE IF EXISTS arp_entries")  # superseded by devices/addresses below

# One row per known device (MAC). hostname/interface are device-level
# attributes, so change-detection for those lives here.
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS devices (
        mac TEXT PRIMARY KEY,
        hostname TEXT,
        interface TEXT,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_ipv6_alert TIMESTAMP
    )
    """
)

# One row per (mac, ip) pair actually observed - a device can legitimately
# hold several concurrent addresses (link-local + global IPv6, temporary
# IPv6 privacy addresses, ...), so this must not collapse to a single
# ipv4/ipv6 value per MAC the way the old arp_entries table did.
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS addresses (
        mac TEXT NOT NULL,
        ip TEXT NOT NULL,
        protocol TEXT NOT NULL,
        interface TEXT,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (mac, ip)
    )
    """
)
cursor.execute("CREATE INDEX IF NOT EXISTS idx_addresses_mac ON addresses (mac)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_addresses_ip ON addresses (ip)")
cursor.execute("CREATE INDEX IF NOT EXISTS idx_addresses_last_seen ON addresses (last_seen)")

# Create events table (append-only log of new entries/changes, used by the
# dashboard widget to show recent activity - devices/addresses only hold
# current state and their last_seen is bumped on every sighting, changed or
# not, so they can't answer "what changed recently" on their own)
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
    new_entry_delay_seconds = config["default"].getint("new_entry_delay_seconds", fallback=15)
    log_mac_changes = config["default"].getboolean("log_mac_changes", fallback=True)
    log_ipv4_changes = config["default"].getboolean("log_ipv4_changes", fallback=False)
    log_ipv6_changes = config["default"].getboolean("log_ipv6_changes", fallback=False)
    ipv6_change_cooldown_hours = config["default"].getint(
        "ipv6_change_cooldown_hours", fallback=0
    )
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

# Shared shutdown/process-tracking state for the passive capture workers
# started in main() - a plain list/lock is enough here since appends/removes
# only happen from the (few) capture worker threads and the signal handler.
_stop_event = threading.Event()
_capture_procs = []
_capture_procs_lock = threading.Lock()

# Module-level so the signal handler can push a wakeup sentinel into it -
# otherwise the main loop can stay blocked in capture_queue.get() for up to
# its poll timeout after SIGTERM, making "service stop"/"restart" (and thus
# the UI Save button, which reconfigures the service) appear to hang.
_capture_queue = queue.Queue()

# Brand-new devices awaiting their delayed "new entry" mail (mac -> epoch
# deadline). Only ever touched from the single-threaded main() loop that
# calls _process_entries()/_flush_pending_new_entries(), so no lock needed.
_pending_new_entries = {}


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
        # Force quoted-printable rather than relying on the default
        # us-ascii/7bit encoding, which has no line-length handling at all -
        # _build_mail_html() returns one unbroken line, and without
        # quoted-printable's self-describing soft line breaks, a relay or
        # mail client hard-wrapping that oversized line wherever it happens
        # to land can corrupt content mid-token (e.g. splitting a CSS hex
        # color in half, breaking that declaration).
        qp_charset = Charset("utf-8")
        qp_charset.body_encoding = QP
        msg.attach(MIMEText(_build_mail_text(event), "plain", qp_charset))
        msg.attach(MIMEText(_build_mail_html(event), "html", qp_charset))

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


def _append_observation(observations, mac, proto, ip, interface):
    if ignore_case:
        mac = mac.lower()
        if proto == "ipv6":
            ip = ip.lower()
    observations.append((mac, proto, ip, interface))


def _startup_snapshot():
    # One-shot arp/ndp table dump, used only to seed state when the daemon
    # (re)starts, so devices the kernel already has a resolved neighbor-cache
    # entry for show up immediately instead of waiting for their next
    # ARP/NDP announcement. Ongoing detection is done by the passive capture
    # workers below, which - unlike arp -an/ndp -an - can also see devices
    # that never get a kernel-resolved entry at all (e.g. a DHCP-less device
    # that only ever announces a link-local/APIPA address).
    observations = []

    if protocols == "all" or protocols == "ipv4_only":
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

        for entry in [e for e in current_ipv4_entries if e]:
            ipv4, mac, interface = entry.split()
            _append_observation(observations, mac, "ipv4", ipv4, interface)

    if protocols == "all" or protocols == "ipv6_only":
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

        for entry in [e for e in current_ipv6_entries if e]:
            ipv6, mac, interface = entry.split()
            _append_observation(observations, mac, "ipv6", ipv6, interface)

    return observations


def _latest_address(mac, proto):
    cursor.execute(
        "SELECT ip FROM addresses WHERE mac = ? AND protocol = ? ORDER BY last_seen DESC LIMIT 1",
        (mac, proto),
    )
    row = cursor.fetchone()
    return row[0] if row else "unknown"


def _device_ip_list(mac, proto):
    cursor.execute(
        "SELECT ip FROM addresses WHERE mac = ? AND protocol = ?",
        (mac, proto),
    )
    ips = [row[0] for row in cursor.fetchall()]
    try:
        # Numeric/address-value order, not lexicographic ("10.0.0.1" would
        # otherwise sort before "20.0.0.1" but after "100.0.0.1")
        return sorted(ips, key=ipaddress.ip_address)
    except ValueError:
        return sorted(ips)


def _format_ip_list(ips):
    # All currently-known addresses of one protocol for a device, joined for
    # display in messages/mail - deliberately separate from hostname
    # resolution below, which only reverse-DNS-looks-up the latest address
    # per protocol rather than every historical/rotated one (privacy IPv6
    # addresses in particular are numerous and essentially never have a PTR
    # record, so resolving all of them on every sighting would be wasted,
    # blocking DNS work for no benefit).
    return "; ".join(ips) if ips else "unknown"


def _hostname_inputs(mac, proto, ip):
    # Representative current address per protocol for this device: the one
    # just observed for its own protocol, and whatever was last seen for the
    # other protocol (a device can hold several concurrent addresses per
    # protocol - this intentionally only looks at the most recent one rather
    # than resolving every address it has ever used).
    ipv4 = ip if proto == "ipv4" else _latest_address(mac, "ipv4")
    ipv6 = ip if proto == "ipv6" else _latest_address(mac, "ipv6")
    return ipv4, ipv6


def _resolve_hostname_for_device(ipv4, ipv6):
    hostname = resolve_hostname(ipv4) + resolve_hostname(ipv6)
    if ignore_case:
        hostname = [name.lower() for name in hostname]

    # Remove duplicates and sort the hostname list
    hostname = sorted(set(hostname))
    # Filter out empty strings
    hostname = [name for name in hostname if name]

    if not hostname:
        return "unknown"
    # split by newline, sort and join with ;
    return "; ".join(sorted(hostname))


def _entry_message(prefix, ipv4, ipv6, hostname, mac, vendor, interface, changes_message=None):
    message = (
        f"{prefix} "
        + (f"IPv4: {ipv4} | " if protocols == "all" or protocols == "ipv4_only" else "")
        + (f"IPv6: {ipv6} | " if protocols == "all" or protocols == "ipv6_only" else "")
        + f"Hostname: {hostname} | MAC: {mac} | Vendor: {vendor} | Interface: {interface}"
    )
    if changes_message:
        message += " | " + " | ".join(changes_message)
    return message


def _process_entries(observations, notify=True):
    time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Age out addresses/devices/events not seen within retention_days. A
    # device disappears once every address of it has aged out.
    cursor.execute(
        f"DELETE FROM addresses WHERE last_seen < datetime('now', '-{retention_days} day')"
    )
    cursor.execute("DELETE FROM devices WHERE mac NOT IN (SELECT DISTINCT mac FROM addresses)")
    cursor.execute(
        f"DELETE FROM events WHERE timestamp < datetime('now', '-{retention_days} day')"
    )

    for mac, proto, ip, interface in observations:
        # Skip suppressed MAC addresses (always matched case-insensitively)
        if mac.lower() in suppress_mac:
            continue

        cursor.execute(
            "SELECT hostname, interface, last_ipv6_alert FROM devices WHERE mac = ?", (mac,)
        )
        device_row = cursor.fetchone()
        is_new_device = device_row is None
        device_hostname, device_interface, device_last_ipv6_alert = (
            device_row if device_row else (None, None, None)
        )

        cursor.execute("SELECT 1 FROM addresses WHERE mac = ? AND ip = ?", (mac, ip))
        is_new_address = cursor.fetchone() is None

        # An IP conflict/spoofing candidate: this exact address is already
        # claimed by a *different*, still-active (not yet aged out) MAC.
        # Checked regardless of whether this MAC is otherwise new or known,
        # so a device that already exists for other reasons and starts
        # additionally squatting on someone else's IP is still caught -
        # as is a brand-new MAC immediately claiming an existing device's IP.
        conflicting_mac = None
        if is_new_address:
            cursor.execute(
                "SELECT mac FROM addresses WHERE ip = ? AND mac != ? ORDER BY last_seen DESC LIMIT 1",
                (ip, mac),
            )
            row = cursor.fetchone()
            if row:
                conflicting_mac = row[0]

        # Representative current address per protocol for this device -
        # this device can hold several concurrent addresses per protocol;
        # for hostname resolution and for what's shown in messages/events we
        # only look at the most recently seen one per protocol, same as the
        # old single-value behaviour.
        ipv4, ipv6 = _hostname_inputs(mac, proto, ip)

        # Get hostname: Dnsmasq host overrides and ISC DHCP static mappings
        # are checked before falling back to reverse DNS, since they're
        # authoritative and don't depend on the device actually registering
        # a PTR record
        configured_hostname = lookup_configured_hostname(mac)
        if configured_hostname:
            hostname = configured_hostname.lower() if ignore_case else configured_hostname
        else:
            hostname = _resolve_hostname_for_device(ipv4, ipv6)

        vendor = mac_vendor_check(mac)

        # Persist observed state unconditionally, independent of what (if
        # anything) ends up logged below
        if is_new_device:
            cursor.execute(
                "INSERT INTO devices (mac, hostname, interface, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
                (mac, hostname, interface, time_now, time_now),
            )
        else:
            cursor.execute(
                "UPDATE devices SET hostname = ?, interface = ?, last_seen = ? WHERE mac = ?",
                (hostname, interface, time_now, mac),
            )
        if is_new_address:
            cursor.execute(
                "INSERT INTO addresses (mac, ip, protocol, interface, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
                (mac, ip, proto, interface, time_now, time_now),
            )
        else:
            cursor.execute(
                "UPDATE addresses SET last_seen = ?, interface = ? WHERE mac = ? AND ip = ?",
                (time_now, interface, mac, ip),
            )

        # Every currently-known address of this device (not just the one
        # involved in this observation) for display in messages/mail -
        # computed after the insert/update above so it includes what was
        # just observed.
        display_ipv4 = _format_ip_list(_device_ip_list(mac, "ipv4"))
        display_ipv6 = _format_ip_list(_device_ip_list(mac, "ipv6"))

        # An IP conflict takes priority over "new device"/"new address"
        # framing - matches the original code's precedence.
        if conflicting_mac is not None:
            if notify and log_mac_changes:
                old_vendor = mac_vendor_check(conflicting_mac)
                message = _entry_message(
                    "ARP - Changes detected!", display_ipv4, display_ipv6, hostname, mac, vendor, interface,
                    [f"OLD MAC: {conflicting_mac} | OLD vendor: {old_vendor}"],
                )
                emit_event(
                    "mac_change", mac, display_ipv4, display_ipv6, hostname, interface, time_now, message,
                    {"mac": conflicting_mac, "vendor": old_vendor},
                )
            continue

        if is_new_device:
            if notify and log_new_entries:
                if new_entry_delay_seconds > 0:
                    # Give the other protocol a chance to resolve (e.g. a
                    # device that announces over NDP and ARP a few seconds
                    # apart) before mailing, so it goes out once with both
                    # addresses instead of "New entry" immediately followed
                    # by a near-duplicate "Changes detected".
                    _pending_new_entries[mac] = time.time() + new_entry_delay_seconds
                else:
                    message = _entry_message(
                        "ARP - New entry detected!", display_ipv4, display_ipv6, hostname, mac, vendor, interface
                    )
                    emit_event(
                        "new_entry", mac, display_ipv4, display_ipv6, hostname, interface, time_now, message
                    )
            continue

        if mac in _pending_new_entries:
            # Still settling in from its initial sighting - whatever changed
            # here (new address, resolved hostname, ...) will already be
            # reflected in the single delayed "new entry" mail once the
            # grace period elapses, so don't also fire a separate change
            # notification for it.
            continue

        # Known device, no conflict - check for anything worth logging
        event_tags = []
        changes_message = []
        changed_fields = {}

        if is_new_address:
            proto_enabled = log_ipv4_changes if proto == "ipv4" else log_ipv6_changes
            proto_in_scope = protocols == "all" or protocols == f"{proto}_only"
            if proto_enabled and proto_in_scope:
                on_cooldown = False
                if proto == "ipv6" and ipv6_change_cooldown_hours > 0 and device_last_ipv6_alert:
                    last_alert = datetime.strptime(device_last_ipv6_alert, "%Y-%m-%d %H:%M:%S")
                    on_cooldown = (
                        datetime.now() - last_alert
                    ).total_seconds() < ipv6_change_cooldown_hours * 3600
                if not on_cooldown:
                    event_tags.append("ipv4_change" if proto == "ipv4" else "ipv6_change")
                    if proto == "ipv6":
                        cursor.execute(
                            "UPDATE devices SET last_ipv6_alert = ? WHERE mac = ?", (time_now, mac)
                        )

        if log_hostname_changes and hostname != device_hostname:
            event_tags.append("hostname_change")
            changed_fields["hostname"] = device_hostname
            changes_message.append(f"OLD Hostname: {device_hostname}")

        if log_interface_changes and interface != device_interface:
            event_tags.append("interface_change")
            changed_fields["interface"] = device_interface
            changes_message.append(f"OLD Interface: {device_interface}")

        if event_tags and notify:
            message = _entry_message(
                "ARP - Changes detected!", display_ipv4, display_ipv6, hostname, mac, vendor, interface, changes_message
            )
            emit_event(
                ",".join(event_tags), mac, display_ipv4, display_ipv6, hostname, interface, time_now, message, changed_fields
            )

    conn.commit()


def _next_pending_new_entry_wait():
    # Seconds until the soonest delayed "new entry" mail is due, or None if
    # there's nothing pending - used by main() to size its queue poll
    # timeout so a flush isn't delayed by an otherwise-idle capture_queue.
    if not _pending_new_entries:
        return None
    return max(0.0, min(_pending_new_entries.values()) - time.time())


def _flush_pending_new_entries():
    now = time.time()
    due_macs = [mac for mac, deadline in _pending_new_entries.items() if deadline <= now]

    for mac in due_macs:
        del _pending_new_entries[mac]

        cursor.execute("SELECT hostname, interface, last_seen FROM devices WHERE mac = ?", (mac,))
        row = cursor.fetchone()
        if row is None:
            # Aged out (retention_days) during the grace period - nothing left to report
            continue
        hostname, interface, last_seen = row

        vendor = mac_vendor_check(mac)
        display_ipv4 = _format_ip_list(_device_ip_list(mac, "ipv4"))
        display_ipv6 = _format_ip_list(_device_ip_list(mac, "ipv6"))
        message = _entry_message(
            "ARP - New entry detected!", display_ipv4, display_ipv6, hostname, mac, vendor, interface
        )
        emit_event("new_entry", mac, display_ipv4, display_ipv6, hostname, interface, last_seen, message)

    if due_macs:
        conn.commit()


def _build_bpf_filter():
    # Same packet classes OPNsense's own hostwatch service captures: any ARP
    # packet with a real (non-probe) sender address, and ICMPv6 Neighbor
    # Solicitation (135) / Neighbor Advertisement (136). Reading the address
    # straight out of these packets - instead of relying on arp -an/ndp -an -
    # is what lets a device that never gets a kernel-resolved neighbor-cache
    # entry (e.g. a DHCP-less device that only ever announces a link-local or
    # APIPA address) still get detected.
    parts = []
    if protocols == "all" or protocols == "ipv4_only":
        parts.append("(arp and not src host 0.0.0.0)")
    if protocols == "all" or protocols == "ipv6_only":
        parts.append("(icmp6 and (icmp6[icmp6type] == 135 or icmp6[icmp6type] == 136))")
    return " or ".join(parts)


def _enumerate_all_interfaces():
    # Mirrors ArpNdpLoggingInterfaceField.php: every assigned, non-virtual
    # interface. Used when the plugin's "Interfaces" setting is left empty
    # ("all"), since - unlike arp -an/ndp -an - packet capture has no
    # interface-less "everything" mode on FreeBSD and needs an explicit list
    # of interfaces to attach to.
    try:
        # config.xml is OPNsense's own trusted, root-owned system config, not
        # attacker-supplied input - see the same rationale on
        # _load_hostname_sources() above.
        root = ET.parse(CONFIG_XML_FILE).getroot()
    except (ET.ParseError, OSError) as e:
        logging.error(f"Failed to parse {CONFIG_XML_FILE} for interface list: {e}")
        return []

    ifaces_node = root.find("interfaces")
    if ifaces_node is None:
        return []

    result = []
    for node in ifaces_node:
        if node.find("virtual") is not None:
            continue
        ifname = (node.findtext("if") or "").strip()
        if ifname:
            result.append(ifname)
    return result


def _format_mac(raw):
    return ":".join(f"{b:02x}" for b in raw)


def _parse_arp(frame):
    # Ethernet(14) + ARP(28) for the standard Ethernet/IPv4 case
    if len(frame) < 42:
        return None
    ptype = frame[16:18]
    hlen = frame[18]
    plen = frame[19]
    if ptype != b"\x08\x00" or hlen != 6 or plen != 4:
        return None
    sender_mac = frame[22:28]
    sender_ip = frame[28:32]
    if sender_ip == b"\x00\x00\x00\x00":
        # RFC 5227 probe stage, before the sender has picked an address -
        # already excluded by the BPF filter, but the frame may still reach
        # here if the OS delivered something slightly different than asked
        return None
    return _format_mac(sender_mac), "ipv4", ".".join(str(b) for b in sender_ip)


def _parse_icmpv6_neighbor(frame):
    # Ethernet(14) + IPv6(40) + ICMPv6 NS/NA header up to the target address
    if len(frame) < 78:
        return None
    if frame[20] != 58:  # IPv6 next header != ICMPv6
        return None
    icmp_type = frame[54]
    if icmp_type not in (135, 136):
        return None

    src_addr = frame[22:38]
    if icmp_type == 135 and src_addr == b"\x00" * 16:
        # Duplicate Address Detection: the host doesn't have a source
        # address yet, so the address it's trying to claim only exists in
        # the Neighbor Solicitation's target field
        ip_bytes = frame[62:78]
    else:
        ip_bytes = src_addr

    mac = _format_mac(frame[6:12])
    return mac, "ipv6", socket.inet_ntop(socket.AF_INET6, ip_bytes)


def _parse_frame(frame):
    if len(frame) < 14:
        return None
    ethertype = frame[12:14]
    if ethertype == b"\x08\x06":
        return _parse_arp(frame)
    if ethertype == b"\x86\xdd":
        return _parse_icmpv6_neighbor(frame)
    return None


def _read_exact(stream, n):
    data = b""
    while len(data) < n:
        chunk = stream.read(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def _read_capture_stream(interface, stream, out_queue):
    # tcpdump is run with -w - (classic pcap format) and -U (flush after
    # every packet), read directly here instead of parsing tcpdump's
    # human-readable text output, since the pcap file format and the raw
    # Ethernet/ARP/IPv6/ICMPv6 wire formats are stable across tcpdump
    # versions in a way its print formatting is not.
    header = _read_exact(stream, 24)
    if header is None:
        return
    (magic,) = struct.unpack("<I", header[:4])
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        endian = "<"
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        endian = ">"
    else:
        logging.error(f"Unexpected pcap header from tcpdump on {interface}: magic {magic:#x}")
        return

    while True:
        record_header = _read_exact(stream, 16)
        if record_header is None:
            return
        _, _, incl_len, _ = struct.unpack(endian + "IIII", record_header)
        frame = _read_exact(stream, incl_len)
        if frame is None:
            return
        parsed = _parse_frame(frame)
        if parsed is not None:
            mac, proto, ip = parsed
            out_queue.put((mac, proto, ip, interface))


def _capture_worker(interface, bpf_filter, out_queue):
    backoff = 1
    while not _stop_event.is_set():
        started = time.time()
        try:
            proc = subprocess.Popen(
                [TCPDUMP_BIN, "-i", interface, "-s", str(TCPDUMP_SNAPLEN), "-w", "-", "-U", "-n", bpf_filter],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError as e:
            logging.error(f"Failed to start tcpdump on {interface}: {e}")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
            continue

        with _capture_procs_lock:
            _capture_procs.append(proc)
        try:
            _read_capture_stream(interface, proc.stdout, out_queue)
        finally:
            proc.wait()
            with _capture_procs_lock:
                if proc in _capture_procs:
                    _capture_procs.remove(proc)

        if _stop_event.is_set():
            break

        logging.warning(f"tcpdump on {interface} exited (code {proc.returncode}), restarting capture")
        backoff = 1 if time.time() - started > 30 else min(backoff * 2, 60)
        time.sleep(backoff)


def _handle_shutdown(_signum, _frame):
    _stop_event.set()
    with _capture_procs_lock:
        procs = list(_capture_procs)
    for p in procs:
        try:
            p.terminate()
        except OSError:
            pass
    # Wake up a main loop blocked in capture_queue.get(timeout=...) right
    # away instead of leaving it to wait out the rest of its poll timeout.
    _capture_queue.put(None)


def main():
    capture_queue = _capture_queue
    bpf_filter = _build_bpf_filter()
    capture_interfaces = interfaces if len(interfaces) > 0 else _enumerate_all_interfaces()

    if len(capture_interfaces) == 0:
        logging.error("No interfaces available to capture on; passive detection is disabled")
    else:
        logging.info(f"Starting passive capture on: {capture_interfaces}")
        for capture_interface in capture_interfaces:
            threading.Thread(
                target=_capture_worker,
                args=(capture_interface, bpf_filter, capture_queue),
                daemon=True,
            ).start()

    # Seed state from the current arp/ndp tables once at startup. On a
    # completely empty database (fresh install, or the state file was
    # removed) this would otherwise report every device already on the
    # network as a "new entry" all at once - suppress notifications for
    # just this initial fill; devices are still recorded, so real changes
    # are reported normally from then on.
    cursor.execute("SELECT 1 FROM devices LIMIT 1")
    initial_fill = cursor.fetchone() is None
    _process_entries(_startup_snapshot(), notify=not initial_fill)

    while not _stop_event.is_set():
        batch = []
        # Cap the poll timeout to the soonest due delayed "new entry" mail
        # (if any), so a quiet capture_queue doesn't hold up its flush.
        pending_wait = _next_pending_new_entry_wait()
        poll_timeout = 60 if pending_wait is None else min(60, pending_wait)
        try:
            item = capture_queue.get(timeout=poll_timeout)
            if item is not None:
                _append_observation(batch, *item)
            while True:
                try:
                    item = capture_queue.get_nowait()
                except queue.Empty:
                    break
                if item is not None:
                    _append_observation(batch, *item)
        except queue.Empty:
            pass

        _process_entries(batch)
        _flush_pending_new_entries()

        # check if the log need to be rotated
        rotate_log()


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
        # Self-hosted mirror (see .github/workflows/update-oui.yml and
        # Scripts/build-oui-csv.py), refreshed weekly - avoids depending on
        # a third-party site's uptime/format/bot-blocking at runtime.
        url = (
            "https://raw.githubusercontent.com/mr-manuel/"
            "opnsense_arp-ndp-logging/refs/heads/mac-vendor-database/oui.csv"
        )
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
    with open(MAC_VENDOR_FILE, "r", encoding="utf-8") as f:
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
            # A matched prefix can still have a blank organization name in
            # the source CSV (seen for e.g. the QEMU/libvirt virtual-NIC
            # OUI) - treat that the same as no match rather than showing an
            # empty value.
            return matches[0] or "unknown"

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

    signal.signal(signal.SIGTERM, _handle_shutdown)
    signal.signal(signal.SIGINT, _handle_shutdown)

    # check if the log need to be rotated
    rotate_log()

    logging.info("*** Starting ARP/NDP Logging ***")

    logging.info(f"protocols: {protocols}")
    logging.info(f"interfaces: {interfaces}")
    logging.info(f"suppress_mac: {suppress_mac}")
    logging.info(f"ignore_case: {ignore_case}")

    mac_vendor_list_download()

    main()
