#!/usr/bin/env python3
"""Upload (or update) the Claroty x PAN pipeline dashboard to the SDL tenant."""
from __future__ import annotations
import json, sys
from pathlib import Path

sys.path.insert(0, "/path/to/.codeium/windsurf/claude-skills/sentinelone-sdl-api/scripts")
import os
os.chdir("/path/to/.codeium/windsurf/claroty-pan-detections")
from sdl_client import SDLClient  # type: ignore

ROOT = Path(__file__).resolve().parent.parent
DASH = ROOT / "dashboards" / "claroty-pan-pipeline.json"
PATH_ON_TENANT = "/dashboards/claroty-pan-pipeline"

content = DASH.read_text()
# Validate JSON locally first
parsed = json.loads(content)
print(f"[+] dashboard local file: {len(parsed.get('graphs',[]))} graphs, {len(content)} bytes")

c = SDLClient()

# Optimistic concurrency: pull current version if exists
existing_version = None
try:
    cur = c.get_file(PATH_ON_TENANT)
    existing_version = cur.get("version")
    print(f"[+] existing version on tenant: {existing_version}")
except Exception as e:
    print(f"[+] no existing dashboard at {PATH_ON_TENANT} (will create): {e}")

kwargs = {"content": content, "prettyprint": True}
if existing_version:
    kwargs["expected_version"] = existing_version
r = c.put_file(PATH_ON_TENANT, **kwargs)
print(f"[+] put_file response: {json.dumps(r, indent=2)[:500]}")
print()
print(f"[+] Dashboard deployed -> {PATH_ON_TENANT}")
print(f"    Open in console: Visualization -> Dashboards -> 'claroty-pan-pipeline'")
