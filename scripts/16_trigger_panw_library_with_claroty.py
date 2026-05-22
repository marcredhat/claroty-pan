#!/usr/bin/env python3
"""Trigger the 7 PANW Library Detection rules with events that ALSO carry the
full Claroty asset context for the src IP. Because Purple AI auto-investigation
reads the alert event's attributes (and the surrounding data lake), embedding
claroty_* fields directly on the event ensures the investigation correlates
PAN behaviour with Claroty inventory before producing a verdict.

Additionally we re-ingest a fresh Claroty inventory snapshot to
`serverHost=claroty-inventory` so Purple AI pivots find a record by src.ip.

This script does NOT create rules - the 7 PANW rules already exist as Library
rules on the tenant. We only need the events to make them fire WITH context.
"""
from __future__ import annotations
import csv, json, time
from pathlib import Path
import requests

ROOT     = Path(__file__).resolve().parent.parent
CLAR_CSV = ROOT / "data" / "claroty_assets.csv"
sdl      = json.loads((ROOT / "config.json").read_text())
SDL_BASE = sdl["base_url"].rstrip("/")
SDL_TOK  = sdl["log_write_key"]
SESSION  = int(time.time())
SH_PAN   = "pan-library-trigger"
SH_CLAR  = "claroty-inventory"


# ---------------- Load Claroty inventory ----------------
inv = {}
with CLAR_CSV.open() as f:
    for row in csv.DictReader(f):
        inv[row["ip"]] = row
print(f"[+] {len(inv)} Claroty assets loaded")


def claroty_attrs(ip: str) -> dict:
    """Build claroty_* attributes for a given src IP (or unmanaged marker)."""
    a = inv.get(ip)
    if not a:
        return {
            "claroty_in_inventory":   "0",
            "claroty_hostname":       "(unmanaged)",
            "claroty_device_type":    "Unknown",
            "claroty_criticality":    "Unknown",
            "claroty_risk":           "0",
            "claroty_site":           "",
            "claroty_zone":           "",
            "claroty_approved_policy":"",
            "claroty_expected_edl":   "",
            "claroty_expected_dag":   "",
            "claroty_status":         "Unknown",
            "claroty_context":        f"{ip} is NOT in Claroty inventory - newly discovered or unmanaged asset.",
        }
    apg = a.get("approved_policy_group", "")
    status = ("Decommissioned" if apg == "decommissioned" else
              "Unassigned"     if apg == "unassigned"     else "Active")
    return {
        "claroty_in_inventory":   "1",
        "claroty_hostname":       a["hostname"],
        "claroty_device_type":    a["device_type"],
        "claroty_criticality":    a["criticality"],
        "claroty_risk":           a["claroty_risk"],
        "claroty_site":           a["site"],
        "claroty_zone":           a["zone"],
        "claroty_approved_policy":apg,
        "claroty_expected_edl":   a["expected_edl"],
        "claroty_expected_dag":   a["expected_dag"],
        "claroty_status":         status,
        "claroty_context": (
            f"{a['hostname']} ({ip}) is a {a['criticality']}-criticality "
            f"{a['device_type']} at {a['site']}/{a['zone']}, Claroty risk={a['claroty_risk']}, "
            f"status={status}. Approved policy group: {apg or '(none)'}. "
            f"Expected EDL='{a['expected_edl']}', expected DAG='{a['expected_dag']}'."
        ),
    }


# ---------------- 7 PANW Library triggers ----------------
TRIGGERS = [
    ("PANW Firewall High Severity Correlation Event Detected",
     "10.30.50.51", {
        "metadata.log_name": "CORRELATION",
        "unmapped.severity": "high",
        "message":           "Correlation: multiple high-severity events from 10.30.50.51",
    }),
    ("PANW Firewall Malware Allowed",
     "10.20.20.21", {
        "metadata.log_name":   "THREAT",
        "unmapped.sub_type":   "virus",
        "unmapped.action":     "alert",
        "action":              "allow",
        "unmapped.threat_name":"Trojan.Win32.Demo",
    }),
    ("PANW Firewall Medium Severity Correlation Event Detected",
     "10.30.10.11", {
        "metadata.log_name": "CORRELATION",
        "unmapped.severity": "medium",
        "message":           "Correlation: medium severity grouped events on plant-b",
    }),
    ("PANW Firewall TOR Traffic Allowed",
     "10.20.30.31", {
        "metadata.log_name": "TRAFFIC",
        "app_name":          "tor",
        "unmapped.action":   "allow",
        "dst.ip.address":    "185.220.101.5",
    }),
    ("PANW Firewall Traffic to Malicious URL Allowed",
     "10.30.50.51", {
        "metadata.log_name":         "THREAT",
        "unmapped.sub_type":         "url",
        "unmapped.url_category":     "malware",
        "unmapped.threat_category":  "malware",
        "unmapped.severity":         "high",
        "unmapped.action":           "alert",
        "action":                    "allow",
        "unmapped.url":              "http://evil-c2-demo.example/payload",
    }),
    ("PANW Firewall Traffic to Phishing URL Allowed",
     "10.30.50.51", {
        "metadata.log_name":         "THREAT",
        "unmapped.sub_type":         "url",
        "unmapped.url_category":     "malware",
        "unmapped.threat_category":  "malware",
        "unmapped.severity":         "medium",
        "unmapped.action":           "alert",
        "action":                    "allow",
        "unmapped.url":              "https://phish-demo.example/login",
    }),
    ("PANW Firewall Unauthorized Config Change",
     "10.20.99.99", {
        "unmapped.type":    "CONFIG",
        "unmapped.result":  "Unauthorized",
        "unmapped.admin":   "demo-attacker",
    }),
]

base_attrs = {
    "dataSource.name":     "Palo Alto Networks Firewall",
    "dataSource.vendor":   "Palo Alto Networks",
    "dataSource.category": "security",
    "serverHost":          SH_PAN,
    "session_id":          str(SESSION),
}

events = []
for i, (rule_name, src_ip, attrs) in enumerate(TRIGGERS):
    a = dict(base_attrs)
    a.update(attrs)
    a["src.ip.address"] = src_ip
    a["library_rule_target"] = rule_name
    a.update(claroty_attrs(src_ip))
    events.append({
        "ts":    int((time.time() - 60 + i) * 1_000_000_000),
        "sev":   3,
        "attrs": a,
    })

print(f"[+] built {len(events)} PANW trigger events with Claroty context")
for e in events:
    a = e["attrs"]
    print(f"   - rule={a['library_rule_target'][:55]:55} src={a['src.ip.address']:14} "
          f"clar={a['claroty_in_inventory']} crit={a['claroty_criticality']:8} "
          f"risk={a['claroty_risk']:3} status={a['claroty_status']}")

# ---------------- Ingest PAN trigger events ----------------
r = requests.post(f"{SDL_BASE}/api/addEvents", timeout=60,
                  json={"token": SDL_TOK,
                        "session": f"pan-lib-trig-{SESSION}",
                        "events": events})
print(f"[+] addEvents PAN -> {r.status_code} {r.text[:200]}")


# ---------------- Refresh Claroty inventory snapshot ----------------
clar_events = []
ts0 = int((time.time() - 30) * 1_000_000_000)
for i, (ip, row) in enumerate(inv.items()):
    a = {
        "dataSource.name":     "Claroty",
        "dataSource.vendor":   "Claroty",
        "dataSource.category": "asset_inventory",
        "serverHost":          SH_CLAR,
        "ip":                  ip,
        "session_id":          str(SESSION),
    }
    for k, v in row.items():
        a[f"claroty_{k}"] = v
    a["message"] = (
        f"Claroty asset {row['hostname']} ({ip}) - {row['criticality']} "
        f"{row['device_type']} at {row['site']}/{row['zone']}, "
        f"risk={row['claroty_risk']}, policy={row['approved_policy_group']}, "
        f"expected_edl={row['expected_edl']}, expected_dag={row['expected_dag']}"
    )
    clar_events.append({"ts": ts0 + i * 1_000_000, "sev": 1, "attrs": a})

r = requests.post(f"{SDL_BASE}/api/addEvents", timeout=60,
                  json={"token": SDL_TOK,
                        "session": f"clar-inv-{SESSION}",
                        "events": clar_events})
print(f"[+] addEvents Claroty inventory ({len(clar_events)}) -> {r.status_code} {r.text[:200]}")

print()
print("[+] Done.")
print("    - 7 PANW Library trigger events ingested WITH claroty_* fields on each event")
print("    - 30 Claroty inventory events refreshed under serverHost=claroty-inventory")
print()
print("    Library rules evaluate every ~5 min. The resulting alerts will support")
print("    'Start Auto-Investigation' from Purple AI, and the investigation will see")
print("    the claroty_* fields on the alert event PLUS the inventory pivots in SDL.")
