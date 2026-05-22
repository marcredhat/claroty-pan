#!/usr/bin/env python3
"""End-to-end runner:
   1. (Re-)generate PAN events with current timestamps
   2. Ingest PAN events via addEvents
   3. Ingest Claroty inventory via addEvents
   4. Build the 'claroty_assets' lookup via savelookup
   5. Run the 5 drift detections and report fire/miss
"""
from __future__ import annotations
import importlib.util, sys, time, uuid, json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))

import config_loader  # noqa: F401
from sdl_client import SDLClient

def _import(modpath: Path):
    spec = importlib.util.spec_from_file_location(modpath.stem, modpath)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# Regenerate PAN events with fresh timestamps
print("=" * 78)
print("STEP 1 — Regenerate PAN events with current timestamps")
print("=" * 78)
_import(ROOT / "scripts" / "02_generate_pan.py")  # writes pan_events.jsonl


c = SDLClient()
print(f"[+] tenant: {c.base_url}\n")

# Ingest PAN
print("=" * 78)
print("STEP 2 — Ingest PAN events")
print("=" * 78)
pan_events = [json.loads(l) for l in (ROOT/"data"/"pan_events.jsonl").read_text().splitlines() if l.strip()]
session = f"pan-{uuid.uuid4().hex[:8]}"
r = c.add_events(session=session, events=pan_events)
print(f"  PAN events ingested ({len(pan_events)}, session={session}): {r}")

# Ingest Claroty
print("\n" + "=" * 78)
print("STEP 3 — Ingest Claroty inventory events")
print("=" * 78)
claroty_mod = _import(ROOT / "scripts" / "05_ingest_claroty_events.py")
# 05 has its own main(); re-run it
import csv
now_ns = int(time.time() * 1_000_000_000)
rows = list(csv.DictReader((ROOT/"data"/"claroty_assets.csv").open()))
events = []
for i, rrow in enumerate(rows):
    events.append({
        "ts": str(now_ns + i * 1_000_000),
        "attrs": {
            "dataSource.name":          "Claroty",
            "dataSource.vendor":        "Claroty",
            "dataSource.category":      "asset_inventory",
            "event.type":               "inventory",
            "serverHost":               "claroty-inventory",
            "ip":                       rrow["ip"],
            "mac":                      rrow["mac"],
            "hostname":                 rrow["hostname"],
            "site":                     rrow["site"],
            "zone":                     rrow["zone"],
            "device_type":              rrow["device_type"],
            "vendor":                   rrow["vendor"],
            "model":                    rrow["model"],
            "criticality":              rrow["criticality"],
            "claroty_risk":             rrow["claroty_risk"],
            "approved_policy_group":    rrow["approved_policy_group"],
            "expected_edl":             rrow["expected_edl"],
            "expected_dag":             rrow["expected_dag"],
            "message":                  f"Claroty inventory: {rrow['hostname']}",
        },
    })
session = f"claroty-{uuid.uuid4().hex[:8]}"
r = c.add_events(session=session, events=events)
print(f"  Claroty events ingested ({len(events)}, session={session}): {r}")

print("\n[+] waiting 25s for indexing...")
time.sleep(25)

# Build lookup
print("\n" + "=" * 78)
print("STEP 4 — Build claroty_assets lookup via savelookup")
print("=" * 78)
build_lookup = """dataSource.name='Claroty' and serverHost='claroty-inventory'
| filter ip != null
| sort timestamp
| group device_type=first(device_type),
        criticality=first(criticality),
        claroty_risk=first(claroty_risk),
        site=first(site),
        zone=first(zone),
        hostname=first(hostname),
        approved_policy_group=first(approved_policy_group),
        expected_edl=first(expected_edl),
        expected_dag=first(expected_dag)
    by ip
| savelookup 'claroty_assets'"""
r = c.power_query(build_lookup, start_time="10m")
rows = r.get("values") or []
print(f"  saved {rows[0][2] if rows else 0} rows")

print("\n[+] waiting 8s for lookup propagation...")
time.sleep(8)

# Detections
PAN = "serverHost='pan-claroty-demo' and dataSource.name contains 'Palo Alto'"
DETECTIONS = [
    (
        "D1",
        "Critical OT device missing or wrong expected EDL / DAG on src side",
        f"""{PAN}
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
    ),
    (
        "D2",
        "Device reclassified in Claroty but PAN tagging is stale",
        f"""{PAN}
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
    ),
    (
        "D3",
        "Newly discovered / unmanaged asset communicating across zones",
        f"""{PAN}
        | lookup device_type, approved_policy_group, site
            from claroty_assets by ip = src.ip.address
        | filter approved_policy_group == 'unassigned'
              or device_type == 'Unknown'
        | filter src_zone != dst_zone
        | group hits=count()
            by src.ip.address, device_type, site, src_zone, dst_zone
        | sort -hits""",
    ),
    (
        "D4",
        "High-risk Claroty asset communicating outside its approved zones",
        f"""{PAN}
        | lookup device_type, claroty_risk, approved_policy_group, site, zone
            from claroty_assets by ip = src.ip.address
        | filter device_type != null
        | filter claroty_risk >= '80'
        | filter dst_zone in ('IT-CORP','INTERNET','DMZ','GUEST')
        | group hits=count()
            by src.ip.address, device_type, claroty_risk, site,
               src_zone, dst_zone, application
        | sort -hits""",
    ),
    (
        "D5",
        "Decommissioned Claroty asset still in active EDL / DAG",
        f"""{PAN}
        | lookup device_type, criticality
            from claroty_assets by ip = src.ip.address
        | filter device_type == 'Decommissioned' or criticality == 'None'
        | filter src_external_dynamic_list != ''
              and src_external_dynamic_list != 'unknown'
        | group hits=count()
            by src.ip.address, device_type, criticality,
               src_external_dynamic_list, src_dynamic_address_group""",
    ),
]

print("\n" + "=" * 78)
print("STEP 5 — Run the 5 detections")
print("=" * 78)
fired = 0
for code, desc, q in DETECTIONS:
    print("\n" + "-" * 78)
    print(f"  {code} — {desc}")
    print("-" * 78)
    try:
        r = c.power_query(query=q.strip(), start_time="2h")
        rows = r.get("values") or []
        cols = [col.get("name","") if isinstance(col,dict) else col
                for col in (r.get("columns") or [])]
        if rows:
            print(f"  FIRE  ({len(rows)} group(s))")
            print("  " + " | ".join(cols))
            for row in rows[:10]:
                print("  " + " | ".join(str(v)[:30] for v in row))
            fired += 1
        else:
            print("  miss  (0 rows)")
    except Exception as e:
        print(f"  ERR   {str(e)[:300]}")

print("\n" + "=" * 78)
print(f"RESULT: {fired}/{len(DETECTIONS)} detections FIRED")
print("=" * 78)
