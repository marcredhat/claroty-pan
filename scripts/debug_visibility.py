#!/usr/bin/env python3
"""Find out where (and whether) our ingested PAN/Claroty events actually
land in the data lake."""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))

import config_loader  # noqa: F401
from sdl_client import SDLClient

c = SDLClient()

probes = [
    ("1. All PAN-Claroty serverHost (24h)",
     "serverHost='pan-claroty-demo' | group n=count() | limit 3", "24h"),
    ("2. All Claroty inventory serverHost (24h)",
     "serverHost='claroty-inventory' | group n=count() | limit 3", "24h"),
    ("3. dataSource.name = Claroty (24h)",
     "dataSource.name='Claroty' | group n=count() | limit 3", "24h"),
    ("4. Any Palo Alto in 24h",
     "dataSource.name contains 'Palo Alto' | group n=count() by serverHost | sort -n | limit 5", "24h"),
    ("5. Pan-claroty-demo with all dataSource",
     "serverHost='pan-claroty-demo' | group n=count() by dataSource.name | sort -n | limit 5", "24h"),
    ("6. Claroty events sample fields",
     "dataSource.name='Claroty' | group n=count() by ip, device_type | sort -n | limit 5", "24h"),
    ("7. Show some recent claroty inv events incl fields",
     "dataSource.name='Claroty' | columns timestamp, ip, device_type, criticality, expected_dag | limit 5", "24h"),
]

for label, q, t in probes:
    print("\n" + "-" * 78)
    print(f"{label}  (start_time={t})")
    print("-" * 78)
    try:
        r = c.power_query(q, start_time=t)
        rows = r.get("values") or []
        cols = [col.get("name","") if isinstance(col,dict) else col
                for col in (r.get("columns") or [])]
        print(f"  rows={len(rows)} cols={cols}")
        for row in rows[:6]:
            print(f"    {row}")
    except Exception as e:
        print(f"  ERR: {str(e)[:300]}")
