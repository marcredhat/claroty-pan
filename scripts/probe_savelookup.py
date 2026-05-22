#!/usr/bin/env python3
"""Identify which form of the savelookup query is accepted on this tenant."""
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
h = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

queries = [
    # 1. Plain Claroty count
    "dataSource.name='Claroty' | group n=count() by ip | limit 3",
    # 2. With first() aggregations
    "dataSource.name='Claroty' | group dt=first(device_type), cr=first(criticality) by ip | limit 3",
    # 3. As above + savelookup
    "dataSource.name='Claroty' | group dt=first(device_type) by ip | savelookup 'claroty_assets'",
    # 4. Different field-name resolution: use double-quoted field names
    'dataSource.name=\'Claroty\' | group dt=first("device_type") by "ip" | limit 3',
    # 5. Maybe the original first() reference needs quotes
    "dataSource.name='Claroty' | group n=count() by ip, device_type | limit 3",
    # 6. Use 'last' instead of 'first'
    "dataSource.name='Claroty' | group dt=last(device_type) by ip | savelookup 'claroty_assets'",
]

for q in queries:
    body = {"query": q, "startTime": "30m"}
    r = requests.post(url, headers=h, data=json.dumps(body))
    print(f"\nQ: {q[:130]}")
    print(f"   HTTP {r.status_code}: {r.text[:400]}")
