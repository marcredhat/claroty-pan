#!/usr/bin/env python3
"""Probe several lookup-table reference syntaxes to find the one accepted
by this SDL tenant. Prints the raw HTTP response body for each."""
from __future__ import annotations
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "vendor"))

import config_loader  # noqa: F401
from sdl_client import SDLClient
import requests

c = SDLClient()
key = c._get_key("log_read")
url = c.base_url + "/api/powerQuery"
headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

probes = [
    "dataset 'config://dataTables/claroty_assets' | limit 3",
    "dataset 'config://datatables/claroty_assets' | limit 3",
    "dataset 'config://lookups/claroty_assets' | limit 3",
    # plain lookup operator
    "serverHost='pan-claroty-demo' | lookup criticality from claroty_assets by ip = 'src.ip.address' | limit 3",
    "serverHost='pan-claroty-demo' | lookup criticality from claroty_assets by ip = src.ip.address | limit 3",
    # with file-path style name
    "serverHost='pan-claroty-demo' | lookup criticality from 'claroty_assets' by ip = src.ip.address | limit 3",
    # with extension
    "serverHost='pan-claroty-demo' | lookup criticality from 'claroty_assets.csv' by ip = src.ip.address | limit 3",
    # with absolute config path
    "serverHost='pan-claroty-demo' | lookup criticality from 'config://dataTables/claroty_assets' by ip = src.ip.address | limit 3",
]

for q in probes:
    body = {"query": q, "startTime": "30m"}
    r = requests.post(url, headers=headers, data=json.dumps(body))
    print(f"\nQ: {q}")
    print(f"   HTTP {r.status_code}")
    try:
        j = r.json()
        # truncate large bodies
        s = json.dumps(j)[:400]
    except Exception:
        s = r.text[:400]
    print(f"   {s}")
