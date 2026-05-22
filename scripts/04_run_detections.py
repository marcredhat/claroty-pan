#!/usr/bin/env python3
"""Run the 5 Claroty x Palo Alto drift detections via PowerQuery and report
which ones fire on the ingested sample data."""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))

import config_loader  # noqa: F401
from sdl_client import SDLClient

c = SDLClient()
PAN  = "serverHost='pan-claroty-demo' and dataSource.name contains 'Palo Alto'"
WIN  = "30m"   # start_time

# Probe 1 — confirm dataset reads from /lookups/<name>
print("\n=== PROBE: dataset 'config://lookups/claroty_assets' ===")
try:
    r = c.power_query("dataset 'config://lookups/claroty_assets' | limit 3", start_time=WIN)
    rows = r.get("values") or []
    print(f"  rows: {len(rows)}, columns: {[col.get('name','') if isinstance(col,dict) else col for col in (r.get('columns') or [])]}")
    for row in rows[:3]:
        print(f"  {row}")
except Exception as e:
    print(f"  ERR: {str(e)[:160]}")

# Probe 2 — lookup operator syntax
print("\n=== PROBE: | lookup ... from claroty_assets ===")
probe = (f"{PAN} | lookup device_type, criticality from claroty_assets "
         f"by ip = src.ip.address | filter device_type != null "
         f"| group n=count() by src.ip.address, device_type, criticality "
         f"| sort -n | limit 5")
try:
    r = c.power_query(probe, start_time=WIN)
    rows = r.get("values") or []
    print(f"  rows: {len(rows)}")
    for row in rows[:5]:
        print(f"  {row}")
except Exception as e:
    print(f"  ERR: {str(e)[:200]}")


# ---------- The five detections ----------
DETECTIONS = [
    (
        "D1 — Critical OT device missing/wrong expected EDL or DAG",
        f"""{PAN}
        | lookup device_type, criticality, expected_edl, expected_dag, site, zone
            from claroty_assets by ip = src.ip.address
        | filter criticality in ('Critical','High')
        | filter src_external_dynamic_list != expected_edl
              or src_dynamic_address_group != expected_dag
        | group hits=count() by src.ip.address, device_type, criticality, site,
                                expected_edl, src_external_dynamic_list,
                                expected_dag, src_dynamic_address_group
        | sort -hits""",
    ),

    (
        "D2 — Device reclassified in Claroty, PAN tagging stale",
        f"""{PAN}
        | lookup device_type, expected_edl, expected_dag, hostname, site
            from claroty_assets by ip = src.ip.address
        | filter device_type != null and device_type != 'Decommissioned'
        | filter src_dynamic_address_group != expected_dag
        | group hits=count(), expected=first(expected_dag),
                actual=first(src_dynamic_address_group)
            by src.ip.address, hostname, device_type, site
        | sort -hits""",
    ),

    (
        "D3 — Newly discovered / unmanaged asset crossing zones",
        f"""{PAN}
        | lookup device_type, approved_policy_group, site
            from claroty_assets by ip = src.ip.address
        | filter approved_policy_group == 'unassigned' or device_type == 'Unknown'
        | filter src_zone != dst_zone
        | group hits=count() by src.ip.address, device_type, site, src_zone, dst_zone
        | sort -hits""",
    ),

    (
        "D4 — High-risk asset communicating outside its approved zone",
        f"""{PAN}
        | lookup device_type, claroty_risk, approved_policy_group, zone, site
            from claroty_assets by ip = src.ip.address
        | filter device_type != null
        | filter claroty_risk >= '80'
        | filter dst_zone in ('IT-CORP','INTERNET','DMZ','GUEST')
        | group hits=count() by src.ip.address, device_type, claroty_risk,
                                site, src_zone, dst_zone, dst.ip.address
        | sort -hits""",
    ),

    (
        "D5 — Decommissioned Claroty asset still in active EDL/DAG",
        f"""{PAN}
        | lookup device_type, criticality, expected_edl
            from claroty_assets by ip = src.ip.address
        | filter device_type == 'Decommissioned' or criticality == 'None'
        | filter src_external_dynamic_list != ''
              and src_external_dynamic_list != 'unknown'
        | group hits=count() by src.ip.address, device_type,
                                src_external_dynamic_list, src_dynamic_address_group
        | sort -hits""",
    ),
]


def run_one(label: str, query: str) -> None:
    print("\n" + "=" * 78)
    print(label)
    print("=" * 78)
    try:
        r = c.power_query(query=query, start_time=WIN)
        rows = r.get("values") or []
        cols = [col.get("name","") if isinstance(col,dict) else col
                for col in (r.get("columns") or [])]
        if rows:
            print(f"  FIRE  ({len(rows)} matching group(s))")
            header = "  " + "  ".join(f"{c:18}" for c in cols)
            print(header)
            print("  " + "-" * (len(header) - 2))
            for row in rows[:10]:
                print("  " + "  ".join(f"{str(v)[:18]:18}" for v in row))
        else:
            print("  miss  (0 rows)")
    except Exception as e:
        print(f"  ERR   {str(e)[:200]}")


total = len(DETECTIONS)
print(f"\nRunning {total} detections against {c.base_url}")
for label, q in DETECTIONS:
    run_one(label, q.strip())

print("\nDone.")
