#!/usr/bin/env python3
"""Ingest the Claroty CSV as addEvents() events tagged dataSource.name='Claroty'.

This makes the asset inventory queryable side-by-side with PAN traffic so we
can use `| join (...), (...) on ip = src.ip.address` for detections.

Why events and not the /lookups/ file path: SDL's `lookup` operator only sees
lookup tables produced by `savelookup`. Putting a CSV at /lookups/<name> stores
the file but does not register it as a lookup table. Two cleaner options:
  (a) ingest as events + use `| join` (this script)
  (b) run a one-shot query that ends in `savelookup 'claroty_assets'`
This package ships (a). Step (b) is documented in README.
"""
from __future__ import annotations
import csv, sys, time, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))

import config_loader  # noqa: F401
from sdl_client import SDLClient

CSV_PATH = ROOT / "data" / "claroty_assets.csv"

def main() -> None:
    c = SDLClient()
    print(f"[+] tenant: {c.base_url}")

    rows = list(csv.DictReader(CSV_PATH.open()))
    print(f"[+] read {len(rows)} Claroty assets")

    now_ns = int(time.time() * 1_000_000_000)
    events = []
    for i, r in enumerate(rows):
        attrs = {
            "dataSource.name":          "Claroty",
            "dataSource.vendor":        "Claroty",
            "dataSource.category":      "asset_inventory",
            "event.type":               "inventory",
            "serverHost":               "claroty-inventory",
            "ip":                       r["ip"],
            "mac":                      r["mac"],
            "hostname":                 r["hostname"],
            "site":                     r["site"],
            "zone":                     r["zone"],
            "device_type":              r["device_type"],
            "vendor":                   r["vendor"],
            "model":                    r["model"],
            "criticality":              r["criticality"],
            "claroty_risk":             r["claroty_risk"],
            "approved_policy_group":    r["approved_policy_group"],
            "expected_edl":             r["expected_edl"],
            "expected_dag":             r["expected_dag"],
            "message":                  f"Claroty inventory: {r['hostname']} ({r['device_type']}) at {r['site']}/{r['zone']}",
        }
        events.append({
            "ts":    str(now_ns + i * 1_000_000),  # 1ms apart
            "attrs": attrs,
        })

    session = f"claroty-{uuid.uuid4().hex[:8]}"
    r = c.add_events(session=session, events=events)
    print(f"[+] ingested via addEvents (session={session}): {r}")


if __name__ == "__main__":
    main()
