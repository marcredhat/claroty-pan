#!/usr/bin/env python3
"""Refine the Library rule list to the subset truly relevant to Claroty x
Palo Alto OT drift, by keyword on name+description and grouped by topic."""
from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
rules = json.loads((ROOT / "hyperautomation" / "library_rules.json").read_text())


def kw(rule, terms):
    h = ((rule.get("name") or "") + " " + (rule.get("description") or "")).lower()
    return any(t in h for t in terms)


buckets = {
    "Claroty":          ["claroty"],
    "Palo Alto":        ["palo alto", "pan-os", "panos", "pan os"],
    "OT / SCADA / ICS": [" ot ", "scada", "modbus", "dnp3", "iec61850",
                          "industrial", "operational technology"],
    "EDL / DAG":        ["external dynamic list", "edl ",
                          "dynamic address group", " dag "],
}

for label, terms in buckets.items():
    matches = [r for r in rules if kw(r, terms)]
    print(f"\n=== {label}  ({len(matches)} rules) ===")
    for r in matches[:25]:
        print(f"   [{(r.get('severity') or '?'):8}] {r.get('name','')}")
        # extra: first 120 chars of query if present
        q = r.get("query") or r.get("s1ql") or ""
        if q:
            print(f"       q: {q[:120]}")

# Non-cloud firewall = "firewall" but not AWS/Azure/GCP
non_cloud = [r for r in rules
             if kw(r, ["firewall"])
             and not kw(r, ["aws", "azure", "cloudtrail", "gcp", "google cloud"])]
print(f"\n=== Non-cloud firewall  ({len(non_cloud)} rules) ===")
for r in non_cloud[:20]:
    print(f"   [{(r.get('severity') or '?'):8}] {r.get('name','')}")
