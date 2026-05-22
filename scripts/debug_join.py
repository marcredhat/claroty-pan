#!/usr/bin/env python3
"""Diagnose why the detections return 0 rows by checking each pipeline stage."""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))

import config_loader  # noqa: F401
from sdl_client import SDLClient

c = SDLClient()
PAN = "serverHost='pan-claroty-demo' and dataSource.name contains 'Palo Alto'"

probes = [
    ("A. PAN event count (15m)",
     f"{PAN} | group n=count() | limit 5"),
    ("B. PAN distinct src.ip (15m)",
     f"{PAN} | group n=count() by src.ip.address | sort -n | limit 8"),
    ("C. PAN distinct src_dynamic_address_group",
     f"{PAN} | group n=count() by src_dynamic_address_group | sort -n | limit 8"),
    ("D. Lookup contents - first 5 rows",
     "dataset 'config://lookups/claroty_assets' | limit 5"),
    ("E. After lookup join - sample 5 with all fields",
     f"{PAN} | lookup device_type, criticality, expected_dag, expected_edl "
     f"from claroty_assets by ip = src.ip.address "
     f"| filter device_type != null "
     f"| group n=count() by src.ip.address, device_type, criticality, "
     f"   src_dynamic_address_group, expected_dag, "
     f"   src_external_dynamic_list, expected_edl "
     f"| sort -n | limit 12"),
    ("F. Critical / High asset count after join",
     f"{PAN} | lookup criticality from claroty_assets by ip = src.ip.address "
     f"| filter criticality in ('Critical','High') "
     f"| group n=count() by src.ip.address, criticality | sort -n | limit 10"),
]

for label, q in probes:
    print("\n" + "=" * 78)
    print(label)
    print("=" * 78)
    try:
        r = c.power_query(q, start_time="2h")
        rows = r.get("values") or []
        cols = [col.get("name","") if isinstance(col,dict) else col
                for col in (r.get("columns") or [])]
        print(f"  rows={len(rows)} cols={cols}")
        for row in rows[:12]:
            print(f"    {row}")
    except Exception as e:
        print(f"  ERR: {str(e)[:300]}")
