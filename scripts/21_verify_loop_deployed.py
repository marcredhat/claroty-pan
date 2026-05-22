#!/usr/bin/env python3
"""Verify the polling-loop workflow is deployed correctly on the tenant:
1. List all Claroty/PANW workflow copies and confirm only one is active.
2. Export the active workflow and inspect the Loop action's parameters.
3. Walk the inner subgraph (delay -> http_request -> variable) and print each."""
from __future__ import annotations
import io, json, sys, zipfile
import requests

S1_CFG = "hyperautomation/config.json"
cfg = json.loads(open(S1_CFG).read())
H = {"Authorization": f"ApiToken {cfg['api_token']}"}
BASE = cfg["base_url"].rstrip("/")


def list_workflows():
    r = requests.get(f"{BASE}/web/api/v2.1/hyper-automate/api/public/workflows",
                     headers=H, params={"limit": 100}, timeout=30).json()
    return r.get("data", [])


def export_workflow(wf_id, wf_name=None):
    r = requests.get(f"{BASE}/web/api/v2.1/hyper-automate/api/public/workflow-import-export/export",
                     headers=H, params={"id": wf_id}, timeout=30)
    if r.status_code != 200:
        return None
    z = zipfile.ZipFile(io.BytesIO(r.content))
    # ZIP may contain multiple workflow JSONs - prefer the one whose embedded
    # name matches the wf_name (case-sensitive), else the one with the most
    # actions (heuristic for the requested target).
    candidates = []
    for n in z.namelist():
        if n.endswith(".json"):
            try:
                candidates.append((n, json.loads(z.read(n))))
            except Exception:
                pass
    if not candidates: return None
    if wf_name:
        for n, j in candidates:
            if j.get("name") == wf_name:
                return j
    # Fallback: max actions
    return max(candidates, key=lambda c: len(c[1].get("actions", [])))[1]


def main():
    # 1) List Claroty/PANW workflows and their states
    rows = list_workflows()
    print(f"Total workflows on tenant: {len(rows)}\n")
    print("Claroty/PANW workflow copies:")
    active = []
    active_name = None
    for w in rows:
        inner = (w.get("workflow") or {})
        name = inner.get("name") or "(no name)"
        if "Claroty/PANW" not in name and "Claroty" not in name:
            continue
        state = inner.get("state") or "?"
        print(f"  {state:12}  {name[:75]:75}  id={w['id']}")
        if state == "active":
            active.append(w["id"])
            active_name = name
    print()
    if len(active) != 1:
        print(f"!! expected exactly 1 active Claroty/PANW workflow, found {len(active)}")
        sys.exit(1)
    print(f"[OK] exactly one Claroty/PANW workflow active: {active[0]}  ({active_name!r})\n")

    # 2) Export the active workflow and find the loop
    wf = export_workflow(active[0], wf_name=active_name)
    if not wf:
        print("[!!] could not export workflow"); sys.exit(1)
    by_id = {a["export_id"]: a for a in wf["actions"]}
    print(f"Workflow '{wf.get('name')}'  -- {len(wf['actions'])} actions total\n")
    loop_action = None
    for a in wf["actions"]:
        d = (a.get("action") or {}).get("data") or {}
        if d.get("action_type") == "loop":
            loop_action = a; break
    if not loop_action:
        print("[!!] NO loop action found"); sys.exit(1)
    ld = (loop_action["action"]["data"])
    print("=== LOOP action ===")
    print(f"  name              : {ld.get('name')}")
    print(f"  loop_type         : {ld.get('loop_type')}")
    print(f"  number_of_iterations: {ld.get('number_of_iterations')}")
    print(f"  object_to_iterate : {ld.get('object_to_iterate')}")
    print(f"  is_parallel       : {ld.get('is_parallel')}")
    print(f"  connected_to      : {loop_action.get('connected_to')}")

    # 3) Walk inner subgraph starting from custom_handle='inner'
    inner_start = next((c["target"] for c in loop_action.get("connected_to", [])
                        if c.get("custom_handle") == "inner"), None)
    if inner_start is None:
        print("[!!] loop has no inner connection"); sys.exit(1)
    print(f"\n=== INNER chain (loop body) ===")
    cur = inner_start
    step = 1
    visited = set()
    while cur is not None and cur not in visited:
        visited.add(cur)
        a = by_id.get(cur)
        if not a:
            print(f"  step {step}: target {cur} not found"); break
        d = (a.get("action") or {}).get("data") or {}
        print(f"  step {step} (id={cur}):  type={d.get('action_type'):14}  name={d.get('name')}")
        if d.get("action_type") == "delay":
            print(f"               -> wait {d.get('value')} {d.get('time_unit')}")
        elif d.get("action_type") == "http_request":
            print(f"               -> POST {d.get('url')}")
        elif d.get("action_type") == "variable":
            for v in (d.get("variables") or [])[:3]:
                print(f"               -> {v['name']:25} <- {v['value'][:80]}")
            if len(d.get("variables") or []) > 3:
                print(f"               -> ... ({len(d['variables'])} variables total)")
        # advance
        ct = a.get("connected_to") or []
        cur = ct[0]["target"] if ct else None
        step += 1
    print(f"\n=== AFTER LOOP (next action when loop completes) ===")
    after = next((c["target"] for c in loop_action.get("connected_to", [])
                  if c.get("custom_handle") in (None, "")), None)
    a = by_id.get(after)
    if a:
        d = (a.get("action") or {}).get("data") or {}
        print(f"  id={after}  type={d.get('action_type')}  name={d.get('name')}")


if __name__ == "__main__":
    main()
