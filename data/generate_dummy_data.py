
"""
data/generate_dummy_data.py

Generates realistic security events and indexes into Elasticsearch.
12 event types mirroring real Wazuh field names.

Usage:
    python data/generate_dummy_data.py --count 2000
    python data/generate_dummy_data.py --count 100 --dry-run
"""

import argparse
import json
import os
import random
import sys
from datetime import datetime, timedelta

from faker import Faker
from opensearchpy import OpenSearch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import settings

fake = Faker()

# ── Event type definitions ─────────────────────────────────────────────────────

EVENT_TYPES = [

    {
        "type": "failed_login",
        "weight": 18,
        "rule": {
            "id": "60122",
            "description": lambda: random.choice([
                "Windows: Multiple failed logon attempts",
                "Linux: Multiple authentication failures",
                "SSH: Brute force attempt detected",
            ]),
            "level": lambda: random.randint(5, 10),
            "groups": ["authentication_failed", "windows", "win_authentication"],
        },
        "extra": lambda: {
            "data": {
                "srcip": fake.ipv4_public(),
                "dstip": fake.ipv4_private(),
                "win": {"eventdata": {
                    "subjectUserName": random.choice(["admin", "administrator", "root", "john.doe", "service_acct"]),
                    "ipAddress": fake.ipv4_public(),
                    "logonType": str(random.choice([2, 3, 10])),
                    "failureReason": "Wrong password",
                }},
            },
        },
    },

    {
        "type": "successful_login",
        "weight": 14,
        "rule": {
            "id": "60106",
            "description": "Windows: User successfully logged on",
            "level": lambda: random.randint(2, 4),
            "groups": ["authentication_success", "windows"],
        },
        "extra": lambda: {
            "data": {
                "srcip": fake.ipv4(),
                "win": {"eventdata": {
                    "subjectUserName": fake.user_name(),
                    "ipAddress": fake.ipv4(),
                    "logonType": str(random.choice([2, 3, 10])),
                }},
            },
        },
    },

    {
        "type": "malware_detection",
        "weight": 8,
        "rule": {
            "id": "87102",
            "description": lambda: random.choice([
                "Malware detected: Ransomware activity",
                "Trojan activity detected on endpoint",
                "Suspicious executable flagged by AV",
                "Cryptominer detected",
                "Rootkit activity detected",
            ]),
            "level": lambda: random.randint(10, 15),
            "groups": ["malware", "attack", "gdpr_iv_35.7.d"],
        },
        "extra": lambda: {
            "data": {
                "srcip": fake.ipv4_private(),
                "file": {
                    "path": random.choice([
                        "C:\\Users\\Public\\Downloads\\setup.exe",
                        "C:\\Temp\\update.bat",
                        "/tmp/suspicious_script.sh",
                        "C:\\Windows\\Temp\\svchost32.exe",
                    ]),
                    "hash": {"md5": fake.md5(), "sha256": fake.sha256()},
                },
                "process": {"name": random.choice(["setup.exe", "update.bat", "powershell.exe", "cmd.exe"])},
            },
        },
    },

    {
        "type": "vpn_login",
        "weight": 10,
        "rule": {
            "id": "87501",
            "description": lambda: random.choice([
                "VPN: User connected successfully",
                "VPN: Failed authentication attempt",
                "VPN: Connection from unusual geographic location",
                "VPN: Multiple concurrent sessions detected",
            ]),
            "level": lambda: random.randint(3, 9),
            "groups": ["vpn", "authentication", "network"],
        },
        "extra": lambda: {
            "data": {
                "srcip": fake.ipv4_public(),
                "dstip": "10.0.0.1",
                "vpn": {
                    "user": fake.user_name(),
                    "server": random.choice(["vpn01.corp", "vpn02.corp", "vpn-us.corp"]),
                    "protocol": random.choice(["OpenVPN", "WireGuard", "IPSec", "SSL-VPN"]),
                    "location": fake.country(),
                    "success": random.choice([True, True, True, False]),
                },
            },
        },
    },

    {
        "type": "mfa_event",
        "weight": 8,
        "rule": {
            "id": "87601",
            "description": lambda: random.choice([
                "MFA: Authentication successful",
                "MFA: Token rejected - invalid OTP",
                "MFA: Push notification denied by user",
                "MFA: Multiple failed MFA attempts - possible attack",
            ]),
            "level": lambda: random.randint(4, 12),
            "groups": ["mfa", "authentication", "2fa"],
        },
        "extra": lambda: {
            "data": {
                "srcip": fake.ipv4(),
                "mfa": {
                    "user": fake.user_name(),
                    "method": random.choice(["TOTP", "Push", "SMS", "Hardware Token"]),
                    "success": random.choice([True, True, False]),
                    "provider": random.choice(["Duo", "Okta", "Azure AD", "Google Auth"]),
                },
            },
        },
    },

    {
        "type": "privilege_escalation",
        "weight": 5,
        "rule": {
            "id": "5402",
            "description": lambda: random.choice([
                "Privilege escalation attempt detected",
                "Sudo usage by non-privileged user",
                "UAC bypass attempt detected",
                "Token impersonation detected",
                "LSASS memory access detected",
            ]),
            "level": lambda: random.randint(10, 14),
            "groups": ["privilege_escalation", "attack", "pci_dss_10.2.5"],
        },
        "extra": lambda: {
            "data": {
                "srcip": fake.ipv4_private(),
                "audit": {
                    "user": fake.user_name(),
                    "command": random.choice(["sudo su", "runas /user:admin", "net localgroup administrators", "whoami /priv"]),
                    "success": random.choice(["yes", "no"]),
                },
            },
        },
    },

    {
        "type": "port_scan",
        "weight": 7,
        "rule": {
            "id": "40101",
            "description": lambda: random.choice([
                "Multiple port scan attempts detected",
                "Nmap scan detected from external IP",
                "Network reconnaissance activity",
                "Service enumeration detected",
            ]),
            "level": lambda: random.randint(8, 12),
            "groups": ["network_scan", "recon", "attack"],
        },
        "extra": lambda: {
            "data": {
                "srcip": fake.ipv4_public(),
                "dstip": fake.ipv4_private(),
                "network": {
                    "ports_scanned": random.randint(100, 65535),
                    "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                    "scan_type": random.choice(["SYN", "FIN", "XMAS", "NULL", "ACK"]),
                },
            },
        },
    },

    {
        "type": "brute_force",
        "weight": 9,
        "rule": {
            "id": "5763",
            "description": lambda: random.choice([
                "Brute force attack detected: multiple authentication failures",
                "SSH brute force from external IP",
                "RDP brute force attempt detected",
                "Web application login brute force",
            ]),
            "level": lambda: random.randint(10, 14),
            "groups": ["authentication_failures", "brute_force", "attack"],
        },
        "extra": lambda: {
            "data": {
                "srcip": fake.ipv4_public(),
                "dstip": fake.ipv4_private(),
                "attempts": random.randint(10, 500),
                "target_user": random.choice(["admin", "root", "administrator", "user"]),
                "service": random.choice(["ssh", "rdp", "ftp", "smtp", "http"]),
            },
        },
    },

    {
        "type": "suspicious_powershell",
        "weight": 6,
        "rule": {
            "id": "91902",
            "description": lambda: random.choice([
                "Suspicious PowerShell execution detected",
                "PowerShell encoded command execution",
                "PowerShell downloading remote payload",
                "Mimikatz detected via PowerShell",
                "PowerShell AMSI bypass attempt",
            ]),
            "level": lambda: random.randint(11, 15),
            "groups": ["attack", "powershell", "windows", "credential_access"],
        },
        "extra": lambda: {
            "data": {
                "srcip": fake.ipv4_private(),
                "process": {
                    "name": "powershell.exe",
                    "command_line": random.choice([
                        "powershell -enc JABzAD0ATgBlAHcA...",
                        "powershell IEX (New-Object Net.WebClient).DownloadString(...)",
                        "powershell -NoP -NonI -W Hidden -Exec Bypass",
                        "Invoke-Mimikatz -DumpCreds",
                        "powershell Set-MpPreference -DisableRealtimeMonitoring $true",
                    ]),
                    "pid": random.randint(1000, 9999),
                    "parent": random.choice(["cmd.exe", "wscript.exe", "winword.exe", "excel.exe"]),
                },
            },
        },
    },

    {
        "type": "file_integrity",
        "weight": 6,
        "rule": {
            "id": "550",
            "description": lambda: random.choice([
                "Integrity checksum changed",
                "File added to monitored directory",
                "File deleted from monitored directory",
                "Registry key modified",
                "Critical system file modified",
            ]),
            "level": lambda: random.randint(7, 11),
            "groups": ["ossec", "syscheck", "pci_dss_11.5"],
        },
        "extra": lambda: {
            "data": {
                "srcip": fake.ipv4_private(),
                "syscheck": {
                    "path": random.choice([
                        "C:\\Windows\\System32\\drivers\\etc\\hosts",
                        "/etc/passwd",
                        "/etc/sudoers",
                        "C:\\Windows\\System32\\cmd.exe",
                        "/etc/crontab",
                    ]),
                    "event": random.choice(["modified", "added", "deleted"]),
                    "md5_before": fake.md5(),
                    "md5_after": fake.md5(),
                },
            },
        },
    },

    {
        "type": "lateral_movement",
        "weight": 4,
        "rule": {
            "id": "18107",
            "description": lambda: random.choice([
                "Lateral movement: Pass-the-hash attempt",
                "Lateral movement: WMI remote execution",
                "Lateral movement: PsExec usage detected",
                "Lateral movement: Remote service installation",
                "Lateral movement: SMB share enumeration",
            ]),
            "level": lambda: random.randint(12, 15),
            "groups": ["lateral_movement", "attack", "windows"],
        },
        "extra": lambda: {
            "data": {
                "srcip": fake.ipv4_private(),
                "dstip": fake.ipv4_private(),
                "technique": random.choice(["Pass-the-Hash", "WMI", "PsExec", "SMB", "RDP"]),
                "mitre_technique": random.choice(["T1550.002", "T1047", "T1569.002", "T1021.002"]),
            },
        },
    },

    {
        "type": "data_exfiltration",
        "weight": 3,
        "rule": {
            "id": "87201",
            "description": lambda: random.choice([
                "Large data transfer to external IP detected",
                "Unusual outbound traffic volume — possible exfiltration",
                "Sensitive file access followed by external transfer",
                "DNS tunneling exfiltration detected",
            ]),
            "level": lambda: random.randint(11, 15),
            "groups": ["data_exfiltration", "attack", "gdpr_iv_35.7.d"],
        },
        "extra": lambda: {
            "data": {
                "srcip": fake.ipv4_private(),
                "dstip": fake.ipv4_public(),
                "network": {
                    "bytes_out": random.randint(10_000_000, 500_000_000),
                    "protocol": random.choice(["HTTPS", "FTP", "DNS", "SFTP"]),
                    "destination_country": fake.country(),
                },
            },
        },
    },
]


def _resolve(value):
    return value() if callable(value) else value


def _weighted_choice(items):
    weights = [e["weight"] for e in items]
    return random.choices(items, weights=weights, k=1)[0]


def build_event(event_type: dict, hours_back: int = 720) -> dict:
    ts = datetime.utcnow() - timedelta(
        hours=random.uniform(0, hours_back),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59),
    )
    rule = event_type["rule"]
    extra = event_type["extra"]()

    base = {
        "timestamp": ts.isoformat(),
        "@timestamp": ts.isoformat(),
        "event_type": event_type["type"],
        "agent": {
            "name": fake.hostname(),
            "id": fake.uuid4(),
            "ip": fake.ipv4_private(),
            "os": {
                "platform": random.choice(["windows", "linux", "macos"]),
                "version": random.choice(["Windows 10", "Windows 11", "Ubuntu 22.04", "CentOS 7", "macOS 14"]),
            },
        },
        "rule": {
            "id": rule["id"],
            "description": _resolve(rule["description"]),
            "level": _resolve(rule["level"]),
            "groups": rule["groups"],
        },
        "location": fake.city(),
        "user": {
            "name": fake.user_name(),
            "domain": random.choice(["CORP", "LOCAL", "WORKGROUP"]),
        },
        "geo": {
            "city": fake.city(),
            "country": fake.country(),
            "country_code": fake.country_code(),
            "coordinates": {"lat": float(fake.latitude()), "lon": float(fake.longitude())},
        },
        "network": {
            "direction": random.choice(["inbound", "outbound", "internal"]),
        },
    }
    base.update(extra)
    return base


def main():
    parser = argparse.ArgumentParser(description="Generate dummy SIEM events")
    parser.add_argument("--count", type=int, default=2000)
    parser.add_argument("--index", type=str, default=settings.es_index)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--hours-back", type=int, default=720,
                        help="Spread events over this many hours back (default: 720 = 30 days)")
    args = parser.parse_args()

    if not args.dry_run:
        es = OpenSearch(
            hosts=[{"host": settings.es_host, "port": settings.es_port}],
            http_auth=(settings.es_user, settings.es_password),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False,
        )
        if not es.ping():
            print("ERROR: Cannot connect to Elasticsearch. Run: docker-compose up -d")
            return

    print(f"Generating {args.count} events across {len(EVENT_TYPES)} event types...")

    success = 0
    for i in range(args.count):
        event_type = _weighted_choice(EVENT_TYPES)
        event = build_event(event_type, hours_back=args.hours_back)

        if args.dry_run:
            if i < 3:
                print(json.dumps(event, indent=2))
        else:
            try:
                es.index(index=args.index, body=event)
                success += 1
                if (i + 1) % 200 == 0:
                    print(f"  Indexed {i + 1}/{args.count}...")
            except Exception as e:
                print(f"  Failed event {i}: {e}")

    if not args.dry_run:
        count = es.count(index=args.index)["count"]
        print(f"\nDone. {success}/{args.count} events indexed.")
        print(f"Total in '{args.index}': {count:,} documents")


if __name__ == "__main__":
    main()