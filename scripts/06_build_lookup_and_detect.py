#!/usr/bin/env python3
"""1) Build the SDL `claroty_assets` lookup table via savelookup, from the
   Claroty events ingested by 05_ingest_claroty_events.py.
2) Wait briefly so the lookup is queryable.
3) Run the five Claroty x Palo Alto drift detections and report fire/miss.

Detection logic implemented:
  D1  Critical / High OT device with wrong or missing src EDL/DAG
  D2  Device reclassified in Claroty but PAN tagging stale
  D3  Newly discovered / unmanaged asset crossing zones
  D4  High-risk asset talking outside its approved zone (IT-CORP/INTERNET)
  D5  Decommissioned Claroty asset still tagged in active EDL
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
print(f"[+] tenant: {c.base_url}\n")

PAN = "serverHost='pan-claroty-demo' and dataSource.name contains 'Palo Alto'"

# ------------------------------------------------------------------
# Step 1 — savelookup: persist the Claroty events as a lookup table
# ------------------------------------------------------------------
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

print("=" * 78)
print("STEP 1 — Building 'claroty_assets' lookup via savelookup")
print("=" * 78)
try:
    r = c.power_query(build_lookup, start_time="30m")
    rows = r.get("values") or []
    print(f"  saved {len(rows)} rows to lookup 'claroty_assets'")
    for row in rows[:5]:
        print(f"    {row}")
except Exception as e:
    print(f"  ERR: {str(e)[:300]}")
    sys.exit(1)

print("\n[+] waiting 8s for lookup propagation...")
time.sleep(8)

# Quick smoke test of the lookup join
print("\n--- smoke test: PAN lookup join (count by criticality) ---")
try:
    sm = (f"{PAN} | lookup criticality from claroty_assets by ip = src.ip.address "
          f"| filter criticality != null | group n=count() by criticality | sort -n")
    r = c.power_query(sm, start_time="30m")
    for row in (r.get("values") or [])[:10]:
        print(f"    {row}")
except Exception as e:
    print(f"  ERR: {str(e)[:300]}")

# ------------------------------------------------------------------
# Step 2 — Detections
# ------------------------------------------------------------------
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


def run_one(idx: int, code: str, desc: str, query: str) -> int:
    print("\n" + "=" * 78)
    print(f"  {code} — {desc}")
    print("=" * 78)
    try:
        r = c.power_query(query=query, start_time="30m")
        rows = r.get("values") or []
        cols = [col.get("name","") if isinstance(col,dict) else col
                for col in (r.get("columns") or [])]
        if rows:
            print(f"  FIRE  ({len(rows)} group(s))")
            print("  " + " | ".join(cols))
            for row in rows[:10]:
                print("  " + " | ".join(str(v)[:32] for v in row))
            return 1
        else:
            print("  miss  (0 rows)")
            return 0
    except Exception as e:
        print(f"  ERR   {str(e)[:300]}")
        return 0


fired = 0
for i, (code, desc, q) in enumerate(DETECTIONS, 1):
    fired += run_one(i, code, desc, q.strip())

print("\n" + "=" * 78)
print(f"RESULT: {fired}/{len(DETECTIONS)} detections FIRED")
print("=" * 78)
