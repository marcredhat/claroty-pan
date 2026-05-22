#!/usr/bin/env python3
"""Import Claroty-Auto-Investigate.json into the SentinelOne console via
the Hyperautomation public API.

Endpoint: POST /web/api/v2.1/hyper-automate/api/public/workflow-import-export/import
Permission required: Hyper Automate.workflowsCreateEdit
Usage:
    python3 hyperautomation/import_workflow.py [--site-id <id>] [--account-id <id>]
At least one of --site-id / --account-id is required (the API needs a scope).
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
import requests

HERE = Path(__file__).resolve().parent
WORKFLOW = HERE / "Claroty-Auto-Investigate.json"
S1_CFG = Path("hyperautomation/config.json")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--site-id",    help="SentinelOne site ID (comma-separated for multiple)")
    ap.add_argument("--account-id", help="SentinelOne account ID (comma-separated for multiple)")
    args = ap.parse_args()
    if not (args.site_id or args.account_id):
        print("[-] need at least --site-id or --account-id", file=sys.stderr)
        return 2

    cfg = json.loads(S1_CFG.read_text())
    base = cfg["base_url"].rstrip("/")
    token = cfg["api_token"]
    h = {"Authorization": f"ApiToken {token}", "Content-Type": "application/json"}

    # Pre-flight: tenant reachable via a known-good endpoint
    r = requests.get(f"{base}/web/api/v2.1/sites", headers=h,
                     params={"limit": 1}, timeout=30)
    if r.status_code != 200:
        print(f"[-] console pre-flight failed: {r.status_code} {r.text[:200]}")
        return 1
    print(f"[+] console reachable: {base}")

    # Token permission check
    r = requests.get(f"{base}/web/api/v2.1/hyper-automate/api/public/workflows",
                     headers=h, params={"limit": 1}, timeout=30)
    if r.status_code in (401, 403):
        print(f"[-] token check failed: {r.status_code} {r.text[:200]}")
        return 1
    print(f"[+] token has Hyper Automate.view permission")

    # Build payload — API expects { "data": {workflow} }
    workflow = json.loads(WORKFLOW.read_text())
    payload = {"data": workflow}

    params = {}
    if args.site_id:    params["siteIds"]    = args.site_id
    if args.account_id: params["accountIds"] = args.account_id

    r = requests.post(
        f"{base}/web/api/v2.1/hyper-automate/api/public/workflow-import-export/import",
        headers=h, params=params, data=json.dumps(payload), timeout=60,
    )
    if r.status_code == 200:
        d = r.json().get("data") or r.json()
        wf_id  = d.get("id")
        ver_id = d.get("version_id")
        print(f"[+] imported: id={wf_id}  name={d.get('name')}  version_id={ver_id}  state={d.get('state')}")
        # Activate the version (workflows land in draft state after import)
        if wf_id and ver_id:
            act_url = (f"{base}/web/api/v2.1/hyper-automate/api/public/workflows/"
                       f"{wf_id}/{ver_id}/activation")
            ar = requests.post(act_url, headers=h,
                               json={"version_description": "Activated via import_workflow.py"},
                               timeout=30)
            if 200 <= ar.status_code < 300:
                print(f"[+] activated version {ver_id}  ({ar.status_code})")
            else:
                print(f"[!] activation failed: {ar.status_code} {ar.text[:200]}")
                print(f"    Manual fallback: POST {act_url}")
        return 0
    print(f"[-] import failed: {r.status_code}")
    try:
        print(json.dumps(r.json(), indent=2)[:1000])
    except Exception:
        print(r.text[:500])
    return 1


if __name__ == "__main__":
    sys.exit(main())
