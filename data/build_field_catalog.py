"""
data/build_field_catalog.py

Builds an expanded FIELD_CATALOG for rag/store.py from:
  1. data/wazuh-template.json  — all Wazuh field names + types
  2. data/wazuh-ECS-mapping.csv — ECS descriptions for known fields

Outputs:
  data/field_catalog.json — drop-in replacement for FIELD_CATALOG in rag/store.py

Usage:
    python data/build_field_catalog.py
    python data/build_field_catalog.py --preview   # show stats only, don't write file
"""

import argparse
import csv
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ECS field descriptions
ECS_DESCRIPTIONS = {
    "agent.ip":               "IP address of the Wazuh agent reporting the event",
    "agent.name":             "Hostname of the Wazuh agent reporting the event",
    "agent.id":               "Unique identifier of the Wazuh agent",
    "agent.version":          "Version of the Wazuh agent",
    "error.code":             "Error code associated with the event",
    "error.message":          "Human readable error message",
    "cloud.account.id":       "Cloud provider account identifier",
    "source.ip":              "Source IP address of the network connection",
    "source.port":            "Source port of the network connection",
    "source.geo.country_name":"Country of origin for the source IP",
    "destination.ip":         "Destination IP address of the network connection",
    "destination.port":       "Destination port of the network connection",
    "user.name":              "Username associated with the security event",
    "user.domain":            "Domain of the user account",
    "process.name":           "Name of the process that triggered the event",
    "process.pid":            "Process identifier",
    "process.command_line":   "Full command line used to launch the process",
    "file.path":              "Full path of the file involved in the event",
    "file.name":              "Name of the file involved in the event",
    "file.hash.md5":          "MD5 hash of the file",
    "file.hash.sha256":       "SHA256 hash of the file",
    "network.direction":      "Direction of network traffic: inbound or outbound",
    "network.protocol":       "Network protocol used: tcp, udp, http, etc",
    "event.action":           "Action that triggered the event",
    "event.category":         "High level category of the event",
    "event.outcome":          "Outcome of the event: success or failure",
    "host.name":              "Hostname where the event occurred",
    "host.ip":                "IP address of the host where event occurred",
    "host.os.name":           "Operating system name of the host",
}

# Wazuh native field descriptions
WAZUH_NATIVE_DESCRIPTIONS = {
    "rule.id":                "Unique identifier of the Wazuh detection rule",
    "rule.level":             "Severity level of the rule from 0 to 15, higher is more severe",
    "rule.description":       "Human readable description of what the rule detected",
    "rule.groups":            "Categories the rule belongs to e.g. authentication_failed malware",
    "rule.mitre.id":          "MITRE ATT&CK technique identifier",
    "rule.mitre.tactic":      "MITRE ATT&CK tactic name",
    "rule.mitre.technique":   "MITRE ATT&CK technique name",
    "rule.pci_dss":           "PCI DSS compliance requirement associated with the rule",
    "rule.gdpr":              "GDPR compliance article associated with the rule",
    "rule.hipaa":             "HIPAA compliance requirement associated with the rule",
    "rule.nist_800_53":       "NIST 800-53 control associated with the rule",
    "data.srcip":             "Source IP address where the attack or event originated",
    "data.dstip":             "Destination IP address targeted by the event",
    "data.srcport":           "Source port number",
    "data.dstport":           "Destination port number",
    "data.protocol":          "Network protocol used in the event",
    "data.url":               "URL associated with the event",
    "data.action":            "Action performed during the event",
    "data.status":            "Status or result of the action",
    "data.win.eventdata.subjectUserName": "Windows event subject username",
    "data.win.eventdata.targetUserName":  "Windows event target username",
    "data.win.eventdata.ipAddress":       "IP address from Windows event log",
    "data.win.eventdata.logonType":       "Windows logon type interactive network service etc",
    "data.win.eventdata.commandLine":     "Command line from Windows process creation event",
    "data.win.eventdata.parentProcessName": "Parent process name from Windows event",
    "data.win.system.eventID":            "Windows Event ID number",
    "data.win.system.channel":            "Windows event log channel Security System Application",
    "data.win.system.computer":           "Computer name from Windows event log",
    "@timestamp":             "Timestamp when the event was detected by Wazuh",
    "timestamp":              "Timestamp when the event was generated at the source",
    "location":               "Log file path or source location that generated the event",
    "full_log":               "Complete raw log entry that triggered the rule",
    "manager.name":           "Name of the Wazuh manager that processed the event",
    "decoder.name":           "Name of the Wazuh decoder used to parse the log",
    "syscheck.path":          "File path monitored by Wazuh FIM File Integrity Monitoring",
    "syscheck.event":         "FIM event type added modified deleted",
    "syscheck.md5_after":     "MD5 hash of file after modification",
    "syscheck.sha256_after":  "SHA256 hash of file after modification",
    "syscheck.size_after":    "File size after modification in bytes",
    "vulnerability.cve":      "CVE identifier for detected vulnerability",
    "vulnerability.severity": "Severity of the detected vulnerability",
    "vulnerability.package.name": "Name of the vulnerable software package",
    "vulnerability.package.version": "Version of the vulnerable software package",
    "GeoLocation.country_name":  "Country name derived from IP geolocation",
    "GeoLocation.city_name":     "City name derived from IP geolocation",
    "GeoLocation.region_name":   "Region name derived from IP geolocation",
}

NL_PHRASES = {
    "rule.level":     ["severity", "level", "high severity", "critical", "low severity", "serious"],
    "rule.groups":    ["category", "type", "attack type", "event type", "classification"],
    "rule.description": ["description", "what happened", "event details", "rule details"],
    "rule.mitre.id":  ["mitre", "att&ck", "technique id", "tactic"],
    "data.srcip":     ["source ip", "from ip", "attacker ip", "origin ip", "client ip"],
    "data.dstip":     ["destination ip", "target ip", "server ip", "victim ip"],
    "agent.name":     ["hostname", "machine", "computer", "endpoint", "host", "agent"],
    "agent.ip":       ["agent ip", "sensor ip", "wazuh agent"],
    "user.name":      ["user", "username", "account", "who", "identity"],
    "@timestamp":     ["time", "when", "date", "timestamp", "occurred"],
    "rule.id":        ["rule id", "rule number", "detection rule"],
    "location":       ["log source", "log file", "source file"],
    "syscheck.path":  ["file path", "monitored file", "fim", "file integrity", "changed file"],
    "syscheck.event": ["file event", "file change", "added deleted modified"],
    "vulnerability.cve": ["cve", "vulnerability", "vuln", "security flaw"],
    "GeoLocation.country_name": ["country", "location", "where", "geography", "origin country"],
    "data.win.system.eventID": ["windows event", "event id", "windows log"],
    "data.win.eventdata.commandLine": ["command", "powershell", "cmd", "script", "executed"],
    "full_log":       ["raw log", "original log", "full message", "log entry"],
}


def flatten_fields(properties, prefix=""):
    fields = {}
    for key, value in properties.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if "properties" in value:
            fields.update(flatten_fields(value["properties"], full_key))
        elif "type" in value:
            fields[full_key] = value["type"]
    return fields


def load_ecs_mapping(csv_path):
    mapping = {}
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if len(row) >= 3 and row[0] and row[2]:
                mapping[row[0].strip()] = row[2].strip()
    return mapping


def get_description(field, ecs_mapping):
    if field in WAZUH_NATIVE_DESCRIPTIONS:
        return WAZUH_NATIVE_DESCRIPTIONS[field]
    ecs_field = ecs_mapping.get(field)
    if ecs_field and ecs_field in ECS_DESCRIPTIONS:
        return ECS_DESCRIPTIONS[ecs_field]
    parts = field.split(".")
    last = parts[-1].replace("_", " ")
    parent = parts[-2].replace("_", " ") if len(parts) > 1 else ""
    return f"{parent} {last}".strip().capitalize()


def get_nl_phrases(field, field_type):
    if field in NL_PHRASES:
        return NL_PHRASES[field]
    parts = field.split(".")
    phrases = [parts[-1].replace("_", " ").lower()]
    if len(parts) > 1:
        phrases.append(f"{parts[-2]} {parts[-1]}".replace("_", " ").lower())
    if field_type == "ip":
        phrases.extend(["ip address", "network address"])
    elif field_type == "date":
        phrases.extend(["time", "when", "date"])
    return list(set(phrases))


def get_query_type(field_type):
    if field_type in ("ip", "keyword", "boolean"):
        return "term"
    elif field_type in ("integer", "long", "float", "double", "date"):
        return "range"
    elif field_type == "text":
        return "match"
    return "term"


def build_catalog(template_path, csv_path):
    with open(template_path) as f:
        template = json.load(f)
    properties = template.get("mappings", {}).get("properties", {})
    all_fields = flatten_fields(properties)
    print(f"Total fields in template: {len(all_fields)}")

    ecs_mapping = load_ecs_mapping(csv_path)
    print(f"Total ECS mappings: {len(ecs_mapping)}")

    catalog = {}
    skipped = 0
    for field, field_type in all_fields.items():
        if any(field.startswith(s) for s in ["_", "smatch", "oscap."]):
            skipped += 1
            continue
        catalog[field] = {
            "description": get_description(field, ecs_mapping),
            "type": field_type,
            "nl_phrases": get_nl_phrases(field, field_type),
            "query_type": get_query_type(field_type),
        }

    print(f"Fields in catalog: {len(catalog)}")
    print(f"Fields skipped: {skipped}")
    return catalog


def write_catalog(catalog, output_path):
    import json
    # Sort keys for consistent output
    sorted_catalog = dict(sorted(catalog.items()))
    with open(output_path, 'w') as f:
        json.dump(sorted_catalog, f, indent=2)
    print(f"\nWritten to: {output_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--preview', action='store_true')
    parser.add_argument('--template', default='data/wazuh-template.json')
    parser.add_argument('--csv', default='data/wazuh-ECS-mapping.csv')
    parser.add_argument('--output', default='data/field_catalog.json')
    args = parser.parse_args()

    print("Building field catalog...")
    catalog = build_catalog(args.template, args.csv)

    print("\nSample entries:")
    for field in list(catalog.keys())[:5]:
        print(f"  {field}: {catalog[field]['description']}")

    if not args.preview:
        write_catalog(catalog, args.output)
        print(f"\nNext: run: python -m rag.store --build")
    else:
        print("\n--preview mode, file not written")


if __name__ == "__main__":
    main()