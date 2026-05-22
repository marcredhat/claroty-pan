#!/usr/bin/env python3
"""Export the 5 detections as standalone .pq files and as STAR-style JSON
detection rule definitions ready to commit to the librarydetections repo."""
from __future__ import annotations
import json, sys, textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_PQ   = ROOT / "detections"
OUT_PQ.mkdir(parents=True, exist_ok=True)

PAN = "serverHost='pan-claroty-demo' and dataSource.name contains 'Palo Alto'"

DETECTIONS = [
    {
        "code": "D1",
        "name": "OT critical asset has wrong or missing Palo Alto EDL/DAG",
        "severity": "High",
        "category": "Policy Drift",
        "description":
            "A device that Claroty classifies as Critical or High is observed in "
            "Palo Alto traffic with an src_external_dynamic_list or "
            "src_dynamic_address_group that does NOT match the value expected by "
            "the Claroty inventory record. Indicates onboarding miss or stale tag.",
        "query": f"""{PAN}
| lookup device_type, criticality, expected_edl, expected_dag, site
    from claroty_assets by ip = src.ip.address
| filter criticality in ('Critical','High')
| filter src_external_dynamic_list != expected_edl
      or src_dynamic_address_group != expected_dag
| group hits=count()
    by src.ip.address, device_type, criticality, site,
       src_external_dynamic_list, expected_edl,
       src_dynamic_address_group, expected_dag
| sort -hits""",
    },
    {
        "code": "D2",
        "name": "OT device reclassified in Claroty but Palo Alto tagging is stale",
        "severity": "Medium",
        "category": "Policy Drift",
        "description":
            "Claroty has updated the device_type for an asset (e.g., HMI -> EWS), "
            "but Palo Alto traffic from that IP still references the previous "
            "dynamic address group. Trigger Hyperautomation to re-tag.",
        "query": f"""{PAN}
| lookup device_type, expected_dag, hostname, site
    from claroty_assets by ip = src.ip.address
| filter device_type != null
      and device_type != 'Decommissioned'
      and device_type != 'Unknown'
| filter src_dynamic_address_group != expected_dag
| group hits=count()
    by src.ip.address, hostname, device_type, site,
       src_dynamic_address_group, expected_dag
| sort -hits""",
    },
    {
        "code": "D3",
        "name": "Newly discovered or unmanaged OT asset crossing zones",
        "severity": "High",
        "category": "Unmanaged Asset",
        "description":
            "An IP that Claroty considers Unknown / unassigned to any policy "
            "group is observed sending Palo Alto traffic ACROSS zones "
            "(src_zone != dst_zone). Likely a freshly attached shadow device.",
        "query": f"""{PAN}
| lookup device_type, approved_policy_group, site
    from claroty_assets by ip = src.ip.address
| filter approved_policy_group == 'unassigned'
      or device_type == 'Unknown'
| filter src_zone != dst_zone
| group hits=count()
    by src.ip.address, device_type, site, src_zone, dst_zone
| sort -hits""",
    },
    {
        "code": "D4",
        "name": "High-risk Claroty asset communicating outside its approved zone",
        "severity": "Critical",
        "category": "Lateral / Exfil",
        "description":
            "A Claroty asset with risk score >= 80 is communicating to a "
            "destination zone that is outside the OT trust boundary "
            "(IT-CORP, INTERNET, DMZ, GUEST). Strong candidate for immediate "
            "EDL block via Hyperautomation.",
        "query": f"""{PAN}
| lookup device_type, claroty_risk, approved_policy_group, site, zone
    from claroty_assets by ip = src.ip.address
| filter device_type != null
| filter claroty_risk >= '80'
| filter dst_zone in ('IT-CORP','INTERNET','DMZ','GUEST')
| group hits=count()
    by src.ip.address, device_type, claroty_risk, site,
       src_zone, dst_zone, application
| sort -hits""",
    },
    {
        "code": "D5",
        "name": "Decommissioned Claroty asset still resolved by an active EDL/DAG",
        "severity": "Medium",
        "category": "Policy Drift",
        "description":
            "Claroty has marked an asset as Decommissioned (criticality=None) "
            "but Palo Alto traffic is still showing it tagged in a production "
            "EDL or DAG. The EDL source is out of sync with Claroty.",
        "query": f"""{PAN}
| lookup device_type, criticality
    from claroty_assets by ip = src.ip.address
| filter device_type == 'Decommissioned' or criticality == 'None'
| filter src_external_dynamic_list != ''
      and src_external_dynamic_list != 'unknown'
| group hits=count()
    by src.ip.address, device_type, criticality,
       src_external_dynamic_list, src_dynamic_address_group""",
    },
]

# Write .pq files (one per detection)
for d in DETECTIONS:
    p = OUT_PQ / f"{d['code']}_{d['name'].replace(' ', '_').replace('/','-')[:60]}.pq"
    p.write_text(d["query"] + "\n")
    print(f"  wrote {p.relative_to(ROOT)}")

# Write STAR-style detection JSON file the librarydetections repo can consume
star_rules = []
for d in DETECTIONS:
    star_rules.append({
        "name":            d["name"],
        "ruleId":          f"claroty-pan-{d['code'].lower()}",
        "severity":        d["severity"],
        "category":        d["category"],
        "description":     d["description"],
        "queryLanguage":   "PowerQuery",
        "queryType":       "events",
        "scheduleType":    "every_5_minutes",
        "expirationMode":  "alert",
        "thresholdHits":   1,
        "groupByFields":   ["src.ip.address", "device_type", "site"],
        "responseActions": [
            "trigger:hyperautomation:update_pan_tag",
            "trigger:hyperautomation:append_pan_edl",
        ],
        "s1ql":            d["query"],
    })

bundle = {
    "name":        "Claroty x Palo Alto Drift",
    "version":     "1.0.0",
    "vendor":      "SentinelOne AI SIEM (library)",
    "description": "Custom detections that correlate Claroty OT asset "
                   "inventory with Palo Alto Networks firewall traffic, "
                   "alerting on policy / tag drift and unmanaged assets.",
    "lookups":     ["claroty_assets"],
    "rules":       star_rules,
}
bundle_path = OUT_PQ / "claroty_pan_drift_rules.json"
bundle_path.write_text(json.dumps(bundle, indent=2))
print(f"\n  wrote {bundle_path.relative_to(ROOT)} ({len(star_rules)} rules)")

# Write a brief INDEX.md inside detections/
idx = OUT_PQ / "INDEX.md"
lines = [
    "# Claroty x Palo Alto Drift detections",
    "",
    "Each `.pq` file is a self-contained SentinelOne PowerQuery alert body.",
    "`claroty_pan_drift_rules.json` bundles them all in the format consumed by",
    "the `librarydetections` repo loader.",
    "",
    "| Code | Severity | Title |",
    "|---|---|---|",
]
for d in DETECTIONS:
    lines.append(f"| {d['code']} | {d['severity']} | {d['name']} |")
lines.append("")
lines.append("Prerequisite lookup: `claroty_assets` (build with `savelookup`).")
idx.write_text("\n".join(lines))
print(f"  wrote {idx.relative_to(ROOT)}")
