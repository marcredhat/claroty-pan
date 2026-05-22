#!/usr/bin/env python3
"""Trigger fresh 'PANW Firewall High Severity Correlation Event Detected'
Library alerts with current timestamps and full Claroty enrichment so the
updated Hyperautomation workflow exercises the GetAutoInvestigationVerdict
path end-to-end."""
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

# Load inventory for enrichment
inv = {}
with CLAR_CSV.open() as f:
    for row in csv.DictReader(f):
        inv[row["ip"]] = row


def claroty_attrs(ip: str) -> dict:
    a = inv.get(ip)
    if not a:
        return {
            "claroty_in_inventory":    "0",
            "claroty_hostname":        "(unmanaged)",
            "claroty_device_type":     "Unknown",
            "claroty_criticality":     "Unknown",
            "claroty_risk":            "0",
            "claroty_site":            "",
            "claroty_zone":            "",
            "claroty_approved_policy": "",
            "claroty_expected_edl":    "",
            "claroty_expected_dag":    "",
            "claroty_status":          "Unknown",
            "claroty_context": f"{ip} is NOT in Claroty inventory.",
        }
    apg = a.get("approved_policy_group", "")
    status = ("Decommissioned" if apg == "decommissioned" else
              "Unassigned"     if apg == "unassigned"     else "Active")
    return {
        "claroty_in_inventory":    "1",
        "claroty_hostname":        a["hostname"],
        "claroty_device_type":     a["device_type"],
        "claroty_criticality":     a["criticality"],
        "claroty_risk":            a["claroty_risk"],
        "claroty_site":            a["site"],
        "claroty_zone":            a["zone"],
        "claroty_approved_policy": apg,
        "claroty_expected_edl":    a["expected_edl"],
        "claroty_expected_dag":    a["expected_dag"],
        "claroty_status":          status,
        "claroty_context": (
            f"{a['hostname']} ({ip}) is a {a['criticality']}-criticality "
            f"{a['device_type']} at {a['site']}/{a['zone']}, Claroty risk={a['claroty_risk']}, "
            f"status={status}. Approved policy group: {apg or '(none)'}."
        ),
    }


# 5 fresh correlation events from different critical OT assets
TARGETS = [
    ("10.30.50.51", "Multi-vector correlation: brute-force + lateral move + suspicious DNS"),
    ("10.20.20.21", "Correlation: HMI scanning internal subnet + outbound to suspicious IP"),
    ("10.30.10.11", "Correlation: PLC abnormal protocol use + multiple failed auth"),
    ("10.20.30.31", "Correlation: EWS off-hours admin login + privilege escalation"),
    ("10.20.99.99", "Correlation: unknown asset scanning OT zones + DNS exfiltration pattern"),
]

base = {
    "dataSource.name":     "Palo Alto Networks Firewall",
    "dataSource.vendor":   "Palo Alto Networks",
    "dataSource.category": "security",
    "serverHost":          "pan-library-trigger",
    "metadata.log_name":   "CORRELATION",
    "unmapped.severity":   "high",
    "session_id":          str(SESSION),
    "library_rule_target": "PANW Firewall High Severity Correlation Event Detected",
}

events = []
now_ns = time.time_ns()
for i, (ip, msg) in enumerate(TARGETS):
    a = dict(base)
    a["src.ip.address"] = ip
    a["message"]        = msg
    a.update(claroty_attrs(ip))
    events.append({
        "ts":    now_ns - (len(TARGETS) - i) * 1_000_000_000,  # last few seconds
        "sev":   3,
        "attrs": a,
    })

print(f"[+] built {len(events)} fresh CORRELATION events, severity=high")
for e in events:
    a = e["attrs"]
    print(f"   - src={a['src.ip.address']:14}  host={a['claroty_hostname']:18}  "
          f"crit={a['claroty_criticality']:8}  risk={a['claroty_risk']:>3}")

r = requests.post(f"{SDL_BASE}/api/addEvents", timeout=60,
                  json={"token": SDL_TOK,
                        "session": f"hi-sev-corr-{SESSION}",
                        "events": events})
print(f"[+] addEvents -> {r.status_code} {r.text[:200]}")
print()
print("[+] Library rule 'PANW Firewall High Severity Correlation Event Detected'")
print("    re-evaluates every ~5 min. Watch Detect -> Findings.")
print(f"    After the alerts surface, the active workflow")
print(f"    'Claroty/PANW Alert ... (2)' (dcec82bf) will fire and exercise the new")
print(f"    GetAutoInvestigationVerdict query.")
