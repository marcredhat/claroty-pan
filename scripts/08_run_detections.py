#!/usr/bin/env python3
"""Run the 5 Claroty x Palo Alto detections against already-ingested data
(does NOT re-ingest). Uses a wider 2h window so previously ingested test
events remain visible.

Pre-requisites:
  - PAN events ingested via 02 + 03 (or 07)
  - Claroty events ingested via 05 (or 07)
  - claroty_assets lookup built via savelookup (07 does this)
"""
from __future__ import annotations
import sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))

import config_loader  # noqa: F401
from sdl_client import SDLClient

c = SDLClient()
print(f"[+] tenant: {c.base_url}")

WIN = "2h"
PAN = "serverHost='pan-claroty-demo' and dataSource.name contains 'Palo Alto'"

# Rebuild lookup defensively
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
r = c.power_query(build_lookup, start_time=WIN)
saved = (r.get("values") or [[None,None,0]])[0][2]
print(f"[+] rebuilt 'claroty_assets' lookup with {saved} rows")
time.sleep(5)

DETECTIONS = [
    (
        "D1", "Critical OT device missing or wrong expected EDL/DAG (src side)",
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
        "D2", "Device reclassified in Claroty but PAN tagging is stale",
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
        "D3", "Newly discovered / unmanaged asset crossing zones",
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
        "D4", "High-risk Claroty asset talking outside its approved zones",
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
        "D5", "Decommissioned Claroty asset still in active EDL/DAG",
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
print(f"Running {len(DETECTIONS)} detections (window={WIN})")
print("=" * 78)

fired = 0
for code, desc, q in DETECTIONS:
    print("\n" + "-" * 78)
    print(f"  {code} — {desc}")
    print("-" * 78)
    try:
        r = c.power_query(q.strip(), start_time=WIN)
        rows = r.get("values") or []
        cols = [col.get("name","") if isinstance(col,dict) else col
                for col in (r.get("columns") or [])]
        if rows:
            print(f"  FIRE  ({len(rows)} group(s))")
            print("    " + " | ".join(f"{c:24}" for c in cols))
            print("    " + "-" * (27 * len(cols)))
            for row in rows[:10]:
                print("    " + " | ".join(f"{str(v)[:24]:24}" for v in row))
            fired += 1
        else:
            print("  miss  (0 rows)")
    except Exception as e:
        print(f"  ERR   {str(e)[:300]}")

print("\n" + "=" * 78)
print(f"RESULT: {fired}/{len(DETECTIONS)} detections FIRED")
print("=" * 78)
