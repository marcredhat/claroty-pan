#!/usr/bin/env python3
"""
Deploy OT/ICS dashboards to SentinelOne Singularity Data Lake.

Reads the two JSON files in this directory and PUTs them to:
  - /dashboards/ot-nozomi-pv-anomaly         (use case 3.2)
  - /dashboards/ot-crown-jewel-safety-plc    (use case 3.3)

Uses the SDLClient from the sibling sentinelone-sdl-api repo.
If your install is elsewhere, set SDL_CLIENT_PATH env var or edit below.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ---- locate SDLClient -------------------------------------------------------
_default = Path.home() / "windsurf/shared/sentinelone-sdl-api/scripts"
SDL_CLIENT_PATH = Path(os.environ.get("SDL_CLIENT_PATH", _default))
if SDL_CLIENT_PATH.exists():
    sys.path.insert(0, str(SDL_CLIENT_PATH))

from sdl_client import SDLClient  # type: ignore  # noqa: E402


DASHBOARDS = [
    ("ot-nozomi-pv-anomaly",       HERE / "nozomi_pv_anomaly.json"),
    ("ot-crown-jewel-safety-plc",  HERE / "crown_jewel_safety_plc_heatmap.json"),
]


def deploy(client: SDLClient, name: str, body_path: Path) -> bool:
    dash_path = f"/dashboards/{name}"
    print(f"\n[*] Deploying: {name}")
    print(f"    Source: {body_path}")
    print(f"    Path:   {dash_path}")

    if not body_path.exists():
        print(f"    [FAIL] Missing JSON: {body_path}")
        return False

    # Validate JSON
    try:
        dashboard_json = json.loads(body_path.read_text())
    except Exception as e:
        print(f"    [FAIL] Invalid JSON: {e}")
        return False

    try:
        existing = client.get_file(dash_path)
        cur_version = existing.get("version")
        print(f"    Existing version: {cur_version}")
    except Exception:
        cur_version = None
        print("    New dashboard (no existing version)")

    body = json.dumps(dashboard_json, indent=2)
    try:
        res = client.put_file(path=dash_path, content=body,
                              expected_version=cur_version)
        if res.get("status") == "success":
            print("    [OK] Deployed")
        else:
            print(f"    [!] Response: {res}")
    except Exception as e:
        print(f"    [FAIL] {e}")
        return False

    time.sleep(2)
    try:
        verify = client.get_file(dash_path)
        new_version = verify.get("version")
        if new_version != cur_version:
            print(f"    [OK] Verified (version: {new_version})")
            return True
        print("    [!] Version did not change")
        return False
    except Exception as e:
        print(f"    [!] Verify failed: {e}")
        return False


def main() -> int:
    print("=" * 60)
    print("OT/ICS Dashboard Deployment")
    print("=" * 60)

    client = SDLClient()
    print(f"Connected to: {client.base_url}")

    results = []
    for name, path in DASHBOARDS:
        results.append((name, deploy(client, name, path)))

    print("\n" + "=" * 60)
    all_ok = all(ok for _, ok in results)
    for name, ok in results:
        print(f"  {name}: {'OK' if ok else 'FAIL'}")
    if all_ok:
        print("\nDone. View at: https://<your-xdr-host>/#/dashboards")
        return 0
    print("\nOne or more deployments failed (see errors above).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
