#!/usr/bin/env python3
"""Upload Claroty CSV as an SDL datatable AND ingest PAN events via addEvents."""
from __future__ import annotations
import json, sys, uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))

import config_loader  # noqa: F401  (loads config.json into env)
from sdl_client import SDLClient

DATATABLE_PATH = "/lookups/claroty_assets"

c = SDLClient()
print(f"[+] tenant: {c.base_url}")

# ---------------- 1. Claroty datatable ----------------
csv_path = ROOT / "data" / "claroty_assets.csv"
csv_content = csv_path.read_text()
print(f"[+] uploading {csv_path.name} ({len(csv_content)} bytes) -> {DATATABLE_PATH}")

# Check if it exists already
try:
    existing = c.get_file(DATATABLE_PATH)
    ver = existing.get("version")
    print(f"    existing version={ver}, replacing")
    r = c.put_file(DATATABLE_PATH, content=csv_content, expected_version=ver)
except Exception:
    r = c.put_file(DATATABLE_PATH, content=csv_content)
print(f"    result: {r}")

# ---------------- 2. PAN events via addEvents ----------------
events_path = ROOT / "data" / "pan_events.jsonl"
events = [json.loads(l) for l in events_path.read_text().splitlines() if l.strip()]
session = f"pan-claroty-{uuid.uuid4().hex[:8]}"
print(f"[+] ingesting {len(events)} PAN events via addEvents (session={session})")
r = c.add_events(session=session, events=events)
print(f"    result: {r}")
print("[+] done. Allow 25-30s for indexing before running detections.")
