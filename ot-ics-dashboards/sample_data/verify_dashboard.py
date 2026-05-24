#!/usr/bin/env python3
"""
Verify the claroty-pan-pipeline dashboard panels see fresh data.

For every graph in dashboards/claroty-pan-pipeline.json with a non-empty
PowerQuery, run the query against SDL over the last hour and print:
  - HTTP status
  - column names
  - row count
  - first row of data

Exit code 0 if every panel returned >= 1 row. Otherwise the names of
the empty panels are printed and exit code is the count of empty panels.

Usage:
    python3 verify_dashboard.py [path/to/config.json]
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DASH = REPO / "dashboards" / "claroty-pan-pipeline.json"

# locate SDLClient the same way ingest_fresh_all.py does
_default = Path.home() / "windsurf/shared/sentinelone-sdl-api/scripts"
sys.path.insert(0, str(Path(os.environ.get("SDL_CLIENT_PATH", _default))))
from sdl_client import SDLClient  # type: ignore


def run_query(c: SDLClient, q: str, plant: str = "*") -> dict:
    """Run a PowerQuery over the last hour. Substitute the $plant token."""
    q = q.replace("$plant", f"'{plant}'") if "$plant" in q else q
    r = requests.post(
        f"{c.base_url}/api/powerQuery",
        headers=c._build_headers("log_read"),
        json={"query": q, "startTime": "1h", "priority": "low"},
        timeout=60, verify=c.verify_tls,
    )
    return r.json() if r.headers.get("content-type", "").startswith("application/json") else {"raw": r.text}


def main(argv):
    cfg = Path(argv[1]) if len(argv) > 1 else None
    if cfg is None:
        client = SDLClient()
    else:
        client = SDLClient(config_path=cfg.expanduser().resolve())
    print(f"[+] tenant: {client.base_url}\n")

    dashboard = json.load(open(DASH))
    empty = []
    for graph in dashboard.get("graphs", []):
        title = graph.get("title", "?")
        q = (graph.get("query") or "").strip()
        if not q:
            print(f"--- {title}")
            print("    (no PowerQuery - markdown / overview panel)\n")
            continue

        print(f"--- {title}")
        # The $plant filter uses '*' for all plants by default.
        plant = "*"
        d = run_query(client, q, plant=plant)
        cols = d.get("columns") or []
        col_names = [x.get("name") if isinstance(x, dict) else x for x in cols]
        rows = d.get("values") or d.get("matches") or d.get("rows") or []
        warn = d.get("warnings")
        if warn:
            print(f"    warnings: {warn}")
        print(f"    columns: {col_names}")
        print(f"    rows:    {len(rows)}")
        for row in rows[:3]:
            # truncate huge rows for readability
            r_str = str(row)
            if len(r_str) > 220:
                r_str = r_str[:217] + "..."
            print(f"      {r_str}")
        if len(rows) == 0:
            empty.append(title)
        print()

    print("=" * 60)
    if empty:
        print(f"EMPTY PANELS ({len(empty)}):")
        for t in empty:
            print(f"  - {t}")
    else:
        print("ALL PANELS RETURN DATA")
    print("=" * 60)
    return len(empty)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
