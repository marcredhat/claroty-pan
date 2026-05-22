#!/usr/bin/env python3
"""Generate sample Palo Alto traffic events.

Events are produced in the pre-mapped OCSF shape used by the librarydetections
trigger pattern (dataSource.name, event.type, src.ip.address, dst.ip.address,
src_zone, dst_zone, action, application, src_external_dynamic_list,
src_dynamic_address_group, ...). They will be sent via addEvents().

Goal: include enough variety to fire each of the 5 detections:
  D1. Critical OT device with no expected EDL/DAG on its src side
  D2. Device was reclassified in Claroty but PAN DAG still reflects old type
  D3. Newly discovered / unmanaged asset talking ACROSS zones
  D4. High-risk Claroty asset communicating OUTSIDE its approved policy_group
       (we approximate by dst_zone outside the approved one for that device)
  D5. PAN traffic references an EDL that no longer matches Claroty inventory
       (the source IP is decommissioned in Claroty but still tagged with the EDL)
"""
from __future__ import annotations
import json, time
from pathlib import Path

DATA_DIR  = Path(__file__).resolve().parent.parent / "data"
OUT_PATH  = DATA_DIR / "pan_events.jsonl"

# Static server host scope marker for verification queries
SERVER_HOST = "pan-claroty-demo"

# Helper: build one event
def ev(i, src_ip, dst_ip, src_zone, dst_zone, action, app, edl, dag,
       device_name="pan-fw-01", etype="traffic", session_end_reason="tcp-fin"):
    return {
        "ts": int((time.time() - 600 + i * 2) * 1_000_000_000),  # last ~10 min
        "attrs": {
            "dataSource.name":               "Palo Alto Networks Firewall",
            "dataSource.vendor":             "Palo Alto Networks",
            "dataSource.category":           "security",
            "event.type":                    etype,
            "serverHost":                    SERVER_HOST,
            "device_name":                   device_name,
            "src.ip.address":                src_ip,
            "dst.ip.address":                dst_ip,
            "src_zone":                      src_zone,
            "dst_zone":                      dst_zone,
            "action":                        action,
            "application":                   app,
            "src_external_dynamic_list":     edl,
            "src_dynamic_address_group":     dag,
            "session_end_reason":            session_end_reason,
            "message":                       f"{etype} {action} {app} {src_ip}->{dst_ip}",
        },
    }

events = []

# -------------------------------------------------------------------
# CLEAN BASELINE — properly tagged traffic that should NOT trigger anything
# -------------------------------------------------------------------
CLEAN = [
    # plc-a-line1-01 -> historian (allowed)
    ("10.20.10.11", "10.20.40.41", "OT-CTRL",  "OT-HISTORIAN",  "allow", "opcua",   "edl-plc-prod",  "dag-plc-prod"),
    ("10.20.10.12", "10.20.40.41", "OT-CTRL",  "OT-HISTORIAN",  "allow", "opcua",   "edl-plc-prod",  "dag-plc-prod"),
    ("10.20.10.13", "10.20.40.41", "OT-CTRL",  "OT-HISTORIAN",  "allow", "opcua",   "edl-plc-prod",  "dag-plc-prod"),
    # hmis -> plc (proper tagging)
    ("10.20.20.21", "10.20.10.11", "OT-HMI",   "OT-CTRL",       "allow", "modbus",  "edl-hmi-prod",  "dag-hmi-prod"),
    ("10.20.20.22", "10.20.10.12", "OT-HMI",   "OT-CTRL",       "allow", "s7comm",  "edl-hmi-prod",  "dag-hmi-prod"),
    # ews -> plc (engineering)
    ("10.20.30.31", "10.20.10.13", "OT-ENG",   "OT-CTRL",       "allow", "ssh",     "edl-ews",       "dag-ews"),
    # ied -> rtac
    ("10.40.10.11", "10.40.20.21", "OT-PROTECT","OT-RTAC",      "allow", "iec61850","edl-ied",       "dag-ied"),
    ("10.40.10.12", "10.40.20.21", "OT-PROTECT","OT-RTAC",      "allow", "iec61850","edl-ied",       "dag-ied"),
    # safety plc local
    ("10.20.70.71", "10.20.10.11", "OT-SAFETY","OT-CTRL",       "allow", "safety-bus","edl-safety", "dag-safety"),
    # rtus -> historian
    ("10.20.50.51", "10.20.40.41", "OT-FIELD", "OT-HISTORIAN",  "allow", "dnp3",    "edl-rtu",       "dag-rtu"),
    ("10.20.50.52", "10.20.40.41", "OT-FIELD", "OT-HISTORIAN",  "allow", "dnp3",    "edl-rtu",       "dag-rtu"),
    # historian replication
    ("10.20.40.41", "10.30.40.41", "OT-HISTORIAN", "OT-HISTORIAN", "allow", "https", "edl-historian", "dag-historian"),
    # drives
    ("10.20.60.61", "10.20.10.11", "OT-DRIVES","OT-CTRL",       "allow", "profinet","edl-drives",    "dag-drives"),
    # plant-b
    ("10.30.10.11", "10.30.40.41", "OT-CTRL",  "OT-HISTORIAN",  "allow", "opcua",   "edl-plc-prod",  "dag-plc-prod"),
    ("10.30.10.12", "10.30.40.41", "OT-CTRL",  "OT-HISTORIAN",  "allow", "opcua",   "edl-plc-prod",  "dag-plc-prod"),
    ("10.30.20.21", "10.30.10.11", "OT-HMI",   "OT-CTRL",       "allow", "modbus",  "edl-hmi-prod",  "dag-hmi-prod"),
    ("10.30.30.31", "10.30.10.12", "OT-ENG",   "OT-CTRL",       "allow", "ssh",     "edl-ews",       "dag-ews"),
    ("10.30.40.41", "10.20.40.41", "OT-HISTORIAN","OT-HISTORIAN","allow", "https",  "edl-historian", "dag-historian"),
    ("10.40.20.21", "10.40.30.31", "OT-RTAC",  "OT-HMI",        "allow", "iec61850","edl-rtac",      "dag-rtac"),
    ("10.40.30.31", "10.40.20.21", "OT-HMI",   "OT-RTAC",       "allow", "iec61850","edl-hmi-prod",  "dag-hmi-prod"),
    # ied -> ied (peer)
    ("10.40.10.11", "10.40.10.12", "OT-PROTECT","OT-PROTECT",   "allow", "goose",   "edl-ied",       "dag-ied"),
    # rtu->plc (allowed within field<->ctrl)
    ("10.20.50.53", "10.20.10.13", "OT-FIELD", "OT-CTRL",       "allow", "dnp3",    "edl-rtu",       "dag-rtu"),
    # dcs controllers
    ("10.20.80.81", "10.20.40.41", "OT-CTRL",  "OT-HISTORIAN",  "allow", "opcua",   "edl-plc-prod",  "dag-plc-prod"),
    ("10.20.80.82", "10.20.40.41", "OT-CTRL",  "OT-HISTORIAN",  "allow", "opcua",   "edl-plc-prod",  "dag-plc-prod"),
    # safety plc plant-b
    ("10.30.70.71", "10.30.10.11", "OT-SAFETY","OT-CTRL",       "allow", "safety-bus","edl-safety", "dag-safety"),
    # vfd plant-b
    ("10.30.60.61", "10.30.10.12", "OT-DRIVES","OT-CTRL",       "allow", "profinet","edl-drives",    "dag-drives"),
    # cisco gateway
    ("10.40.40.41", "10.40.30.31", "OT-GATEWAY","OT-HMI",       "allow", "snmp",    "edl-gateway",   "dag-gateway"),
]

# Repeat clean events to make it look like real traffic volume (each 3x)
i = 0
for cycle in range(3):
    for (sip, dip, sz, dz, act, app, edl, dag) in CLEAN:
        events.append(ev(i, sip, dip, sz, dz, act, app, edl, dag)); i += 1

# -------------------------------------------------------------------
# DRIFT 1: Critical OT devices with WRONG (or missing) EDL/DAG on src side
# plc-a-line1-01 (10.20.10.11): expected edl-plc-prod / dag-plc-prod
#   -> seen with NO EDL/DAG match (typical onboarding miss)
# -------------------------------------------------------------------
for _ in range(4):
    events.append(ev(i, "10.20.10.11", "10.20.40.41", "OT-CTRL", "OT-HISTORIAN",
                     "allow", "opcua", "edl-misc-iot", "dag-misc-iot")); i += 1
# Safety PLC seen with no EDL at all (treated as empty)
for _ in range(3):
    events.append(ev(i, "10.20.70.71", "10.20.10.11", "OT-SAFETY", "OT-CTRL",
                     "allow", "safety-bus", "", "")); i += 1

# -------------------------------------------------------------------
# DRIFT 2: Reclassified device — ews-a-02 (10.20.30.32) is now an EWS in
# Claroty, but its PAN traffic still carries the OLD hmi-prod tags.
# -------------------------------------------------------------------
for _ in range(5):
    events.append(ev(i, "10.20.30.32", "10.20.10.11", "OT-ENG", "OT-CTRL",
                     "allow", "ssh", "edl-hmi-prod", "dag-hmi-prod")); i += 1

# -------------------------------------------------------------------
# DRIFT 3: Newly discovered unmanaged asset (10.20.99.99) communicating
# ACROSS zones (OT-UNKNOWN -> OT-CTRL and OT-HISTORIAN).
# -------------------------------------------------------------------
for j in range(4):
    events.append(ev(i, "10.20.99.99", "10.20.10.11", "OT-UNKNOWN", "OT-CTRL",
                     "allow", "modbus", "unknown", "unknown")); i += 1
    events.append(ev(i, "10.20.99.99", "10.20.40.41", "OT-UNKNOWN", "OT-HISTORIAN",
                     "allow", "https", "unknown", "unknown")); i += 1

# -------------------------------------------------------------------
# DRIFT 4: High-risk Claroty asset (10.30.50.51, claroty_risk=93)
# communicating OUTSIDE its approved policy group. The approved zone
# for controllers is OT-CTRL <-> OT-HISTORIAN; here it crosses to IT-CORP.
# -------------------------------------------------------------------
for _ in range(5):
    events.append(ev(i, "10.30.50.51", "192.168.50.20", "OT-CTRL", "IT-CORP",
                     "allow", "rdp", "edl-plc-prod", "dag-plc-prod")); i += 1
# Also some attempts to internet (very wrong)
for _ in range(2):
    events.append(ev(i, "10.30.50.51", "203.0.113.45", "OT-CTRL", "INTERNET",
                     "allow", "http-proxy", "edl-plc-prod", "dag-plc-prod")); i += 1

# -------------------------------------------------------------------
# DRIFT 5: Decommissioned-in-Claroty IP still in EDL (10.99.99.10).
# Traffic shows it carrying edl-plc-prod even though Claroty marks it
# "Decommissioned".
# -------------------------------------------------------------------
for _ in range(3):
    events.append(ev(i, "10.99.99.10", "10.20.40.41", "OT-CTRL", "OT-HISTORIAN",
                     "allow", "opcua", "edl-plc-prod", "dag-plc-prod")); i += 1


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    print(f"[+] wrote {len(events)} events to {OUT_PATH}")


if __name__ == "__main__":
    main()
