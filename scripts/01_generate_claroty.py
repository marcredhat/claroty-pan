#!/usr/bin/env python3
"""Generate a realistic Claroty OT asset inventory CSV.

Schema (matches the lookup contract used in the detections):
  ip, mac, hostname, site, zone, device_type, vendor, model,
  criticality, claroty_risk, approved_policy_group, expected_edl, expected_dag
"""
from pathlib import Path
import csv

OUT = Path(__file__).resolve().parent.parent / "data" / "claroty_assets.csv"

# Each row designed so we can drive deterministic detection cases later.
ASSETS = [
    # --- SITE: PLANT-A (production line) ---
    # PLCs in OT-CTRL zone
    ("10.20.10.11", "00:1b:1b:11:11:11", "plc-a-line1-01", "PLANT-A", "OT-CTRL",       "PLC",         "Siemens",         "S7-1500",        "Critical", "92", "ot-controllers",  "edl-plc-prod",       "dag-plc-prod"),
    ("10.20.10.12", "00:1b:1b:11:11:12", "plc-a-line1-02", "PLANT-A", "OT-CTRL",       "PLC",         "Siemens",         "S7-1500",        "Critical", "88", "ot-controllers",  "edl-plc-prod",       "dag-plc-prod"),
    ("10.20.10.13", "00:1b:1b:11:11:13", "plc-a-line2-01", "PLANT-A", "OT-CTRL",       "PLC",         "Rockwell",        "ControlLogix",   "Critical", "85", "ot-controllers",  "edl-plc-prod",       "dag-plc-prod"),
    # HMIs in OT-HMI zone
    ("10.20.20.21", "00:1b:1b:22:22:21", "hmi-a-line1-01", "PLANT-A", "OT-HMI",        "HMI",         "Siemens",         "Comfort Panel",  "High",     "70", "ot-hmi",          "edl-hmi-prod",       "dag-hmi-prod"),
    ("10.20.20.22", "00:1b:1b:22:22:22", "hmi-a-line2-01", "PLANT-A", "OT-HMI",        "HMI",         "Wonderware",      "InTouch",        "High",     "68", "ot-hmi",          "edl-hmi-prod",       "dag-hmi-prod"),
    # Engineering workstations
    ("10.20.30.31", "00:1b:1b:33:33:31", "ews-a-01",       "PLANT-A", "OT-ENG",        "EWS",         "Dell",            "Precision-T",    "High",     "75", "ot-engineering",  "edl-ews",            "dag-ews"),
    # Historian
    ("10.20.40.41", "00:1b:1b:44:44:41", "historian-a-01", "PLANT-A", "OT-HISTORIAN",  "Historian",   "OSIsoft",         "PI Server",      "High",     "60", "ot-historian",    "edl-historian",      "dag-historian"),
    # RTUs in field
    ("10.20.50.51", "00:1b:1b:55:55:51", "rtu-a-field-01", "PLANT-A", "OT-FIELD",      "RTU",         "Schneider",       "SCADAPack",      "Medium",   "55", "ot-field",        "edl-rtu",            "dag-rtu"),
    ("10.20.50.52", "00:1b:1b:55:55:52", "rtu-a-field-02", "PLANT-A", "OT-FIELD",      "RTU",         "Schneider",       "SCADAPack",      "Medium",   "50", "ot-field",        "edl-rtu",            "dag-rtu"),
    # Drives / VFDs
    ("10.20.60.61", "00:1b:1b:66:66:61", "vfd-a-line1-01", "PLANT-A", "OT-DRIVES",     "VFD",         "ABB",             "ACS880",         "Medium",   "45", "ot-drives",       "edl-drives",         "dag-drives"),
    # Safety PLC (highest criticality)
    ("10.20.70.71", "00:1b:1b:77:77:71", "splc-a-line1",   "PLANT-A", "OT-SAFETY",     "Safety-PLC",  "Siemens",         "S7-1500F",       "Critical", "95", "ot-safety",       "edl-safety",         "dag-safety"),

    # --- SITE: PLANT-B (assembly) ---
    ("10.30.10.11", "00:1b:2b:11:11:11", "plc-b-line1-01", "PLANT-B", "OT-CTRL",       "PLC",         "Mitsubishi",      "FX5U",           "Critical", "82", "ot-controllers",  "edl-plc-prod",       "dag-plc-prod"),
    ("10.30.10.12", "00:1b:2b:11:11:12", "plc-b-line2-01", "PLANT-B", "OT-CTRL",       "PLC",         "Omron",           "NX1P2",          "High",     "72", "ot-controllers",  "edl-plc-prod",       "dag-plc-prod"),
    ("10.30.20.21", "00:1b:2b:22:22:21", "hmi-b-line1-01", "PLANT-B", "OT-HMI",        "HMI",         "Pro-Face",        "GP4000",         "High",     "65", "ot-hmi",          "edl-hmi-prod",       "dag-hmi-prod"),
    ("10.30.30.31", "00:1b:2b:33:33:31", "ews-b-01",       "PLANT-B", "OT-ENG",        "EWS",         "HP",              "Z2 Mini",        "High",     "70", "ot-engineering",  "edl-ews",            "dag-ews"),
    ("10.30.40.41", "00:1b:2b:44:44:41", "historian-b-01", "PLANT-B", "OT-HISTORIAN",  "Historian",   "AVEVA",           "Historian",      "Medium",   "55", "ot-historian",    "edl-historian",      "dag-historian"),

    # --- SITE: SUBSTATION-1 (energy) ---
    ("10.40.10.11", "00:1b:3b:11:11:11", "ied-sub1-bay1",  "SUB-1",   "OT-PROTECT",    "IED",         "SEL",             "SEL-751",        "Critical", "90", "ot-protection",   "edl-ied",            "dag-ied"),
    ("10.40.10.12", "00:1b:3b:11:11:12", "ied-sub1-bay2",  "SUB-1",   "OT-PROTECT",    "IED",         "ABB",             "REL670",         "Critical", "88", "ot-protection",   "edl-ied",            "dag-ied"),
    ("10.40.20.21", "00:1b:3b:22:22:21", "rtac-sub1-01",   "SUB-1",   "OT-RTAC",       "RTAC",        "SEL",             "RTAC-3530",      "Critical", "85", "ot-rtac",         "edl-rtac",           "dag-rtac"),
    ("10.40.30.31", "00:1b:3b:33:33:31", "hmi-sub1-01",    "SUB-1",   "OT-HMI",        "HMI",         "Siemens",         "Comfort Panel",  "High",     "60", "ot-hmi",          "edl-hmi-prod",       "dag-hmi-prod"),

    # --- SITE: PLANT-A (DCS controllers, mid criticality) ---
    ("10.20.80.81", "00:1b:1b:88:88:81", "dcs-a-ctrl-01",  "PLANT-A", "OT-CTRL",       "DCS",         "Emerson",         "DeltaV",         "High",     "76", "ot-controllers",  "edl-plc-prod",       "dag-plc-prod"),
    ("10.20.80.82", "00:1b:1b:88:88:82", "dcs-a-ctrl-02",  "PLANT-A", "OT-CTRL",       "DCS",         "Yokogawa",        "CENTUM",         "High",     "74", "ot-controllers",  "edl-plc-prod",       "dag-plc-prod"),

    # --- Drift / freshly-reclassified assets ---
    # Recently changed from "HMI" -> "EWS" in Claroty, but PAN tagging is stale (detection 2)
    ("10.20.30.32", "00:1b:1b:33:33:32", "ews-a-02",       "PLANT-A", "OT-ENG",        "EWS",         "Lenovo",          "P3 Tiny",        "High",     "72", "ot-engineering",  "edl-ews",            "dag-ews"),
    # Newly discovered, unmanaged — no tags in Claroty's "approved" view (detection 3)
    ("10.20.99.99", "00:1b:1b:99:99:99", "unknown-a-99",   "PLANT-A", "OT-UNKNOWN",    "Unknown",     "Unknown",         "Unknown",        "Critical", "80", "unassigned",      "unknown",            "unknown"),
    # High-risk asset; "approved" group only allows historian — exfil if elsewhere (detection 4)
    ("10.30.50.51", "00:1b:2b:55:55:51", "plc-b-fuel-01",  "PLANT-B", "OT-CTRL",       "PLC",         "Rockwell",        "CompactLogix",   "Critical", "93", "ot-controllers",  "edl-plc-prod",       "dag-plc-prod"),

    # --- Decommissioned in Claroty but still in PAN EDL (detection 5) ---
    # Note: these IPs no longer in this CSV would imply "stale EDL"; we keep a row with criticality=Decommissioned
    ("10.99.99.10", "00:1b:99:99:99:10", "old-plc-decom",  "PLANT-A", "OT-DECOM",      "Decommissioned","Siemens",       "S7-300",         "None",     "0",  "decommissioned",  "edl-plc-prod",       "dag-plc-prod"),

    # --- More fillers across criticality ---
    ("10.30.60.61", "00:1b:2b:66:66:61", "vfd-b-line1-01", "PLANT-B", "OT-DRIVES",     "VFD",         "Siemens",         "Sinamics",       "Medium",   "48", "ot-drives",       "edl-drives",         "dag-drives"),
    ("10.40.40.41", "00:1b:3b:44:44:41", "gw-sub1-01",     "SUB-1",   "OT-GATEWAY",    "Gateway",     "Cisco",           "IE-4000",        "Medium",   "50", "ot-gateway",      "edl-gateway",        "dag-gateway"),
    ("10.20.50.53", "00:1b:1b:55:55:53", "rtu-a-field-03", "PLANT-A", "OT-FIELD",      "RTU",         "Schneider",       "SCADAPack",      "Medium",   "53", "ot-field",        "edl-rtu",            "dag-rtu"),
    ("10.30.70.71", "00:1b:2b:77:77:71", "splc-b-line1",   "PLANT-B", "OT-SAFETY",     "Safety-PLC",  "Rockwell",        "GuardLogix",     "Critical", "94", "ot-safety",       "edl-safety",         "dag-safety"),
]

HEADERS = [
    "ip","mac","hostname","site","zone","device_type","vendor","model",
    "criticality","claroty_risk","approved_policy_group","expected_edl","expected_dag",
]


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(HEADERS)
        w.writerows(ASSETS)
    print(f"[+] wrote {len(ASSETS)} rows to {OUT}")


if __name__ == "__main__":
    main()
