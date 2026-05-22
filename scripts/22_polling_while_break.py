#!/usr/bin/env python3
"""Refactor the polling block to use a true `while`-loop + `break_loop`
(documented pattern). Replaces the dynamic 10-iter loop with:

    Loop (mode=while, expression=true)
      |
      [inner] Delay 30s -> Get Investigation -> Extract Verdict
                 |
                 v
        Condition "Is Investigation Done?"
                 |true                |false
                 v                    |
            break_loop                |
                                  (next iteration)
"""
from __future__ import annotations
import json, copy
from pathlib import Path

WF = Path("/path/to/.codeium/windsurf/claroty-pan-detections/hyperautomation/Claroty-Auto-Investigate.json")
data = json.loads(WF.read_text())

# Locate the existing loop and its inner subgraph
def find_by_name(substr):
    for a in data["actions"]:
        d = (a.get("action") or {}).get("data") or {}
        if substr in (d.get("name") or ""):
            return a
    return None

loop_act    = find_by_name("Poll Investigation")
inner_delay = find_by_name("Poll Delay 30s")
inner_get   = find_by_name("Get Investigation Result (loop)") or find_by_name("Get Investigation Result loop")
inner_ext   = find_by_name("Extract Verdict (loop)") or find_by_name("Extract Verdict loop")
assert all([loop_act, inner_delay, inner_get, inner_ext]), "expected loop body actions not found"
LOOP_ID = loop_act["export_id"]
print(f"[+] loop id={LOOP_ID}  inner: delay={inner_delay['export_id']} "
      f"get={inner_get['export_id']} extract={inner_ext['export_id']}")

# 1) Convert loop to while+true
loop_data = loop_act["action"]["data"]
loop_data["name"]                 = "Poll Investigation (while true, break on terminal)"
loop_data["loop_type"]            = "while"
loop_data["mode"]                 = "while"
loop_data["expression"]           = "true"
# Keep a numeric safety cap so an infinite loop is impossible if the engine
# falls back to dynamic interpretation. Doubles as the dynamic fallback array.
loop_data["number_of_iterations"] = "20"
loop_data["object_to_iterate"]    = "[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20]"

# 2) Allocate new ids
existing = {a["export_id"] for a in data["actions"]}
next_id = max(existing) + 1
def alloc():
    global next_id; v = next_id; next_id += 1; return v
COND_ID  = alloc()
BREAK_ID = alloc()

# 3) Rewire the extract step to point to the new condition
inner_ext["connected_to"] = [{"target": COND_ID, "custom_handle": None, "payload": None}]

# 4) Build condition + break_loop, both as children of the loop (parent_action = LOOP_ID)
condition_action = {
    "action": {
        "type": "condition",
        "tag": "core_action",
        "connection_id": None, "connection_name": None, "use_connection_name": False, "integration_id": None,
        "data": {
            "name": "Is Investigation Done?",
            "action_type": "condition",
            "condition_type": "multi",
            "condition": None,
            "conditions": [
                {"input_value": "{{local_var.status_ai}}",
                 "compared_value": "[\"COMPLETED\",\"FAILED\",\"RESTRICTED\"]",
                 "comparison_operator": "in"}
            ],
            "conditions_relationship": "and",
            "expression": "{{local_var.status_ai}} in ['COMPLETED','FAILED','RESTRICTED']"
        },
        "state": "active",
        "description": "Exit poll loop as soon as Purple AI reaches a terminal state.",
        "client_data": {"position": {"x": 0, "y": 1200}, "dimensions": {"width": 256, "height": 76}, "collapsed": False},
        "snippet_workflow_id": None, "snippet_version_id": None,
    },
    "export_id": COND_ID,
    "connected_to": [
        {"target": BREAK_ID, "custom_handle": "true",  "payload": None},
        # 'false' has no target: the iteration ends and the while-loop loops.
    ],
    "parent_action": LOOP_ID,
}

break_action = {
    "action": {
        "type": "break_loop",
        "tag": "core_action",
        "connection_id": None, "connection_name": None, "use_connection_name": False, "integration_id": None,
        "data": {
            "name": "Break Poll Loop",
            "action_type": "break_loop"
        },
        "state": "active",
        "description": "Exit the polling loop cleanly when status is terminal.",
        "client_data": {"position": {"x": 200, "y": 1300}, "dimensions": {"width": 256, "height": 76}, "collapsed": False},
        "snippet_workflow_id": None, "snippet_version_id": None,
    },
    "export_id": BREAK_ID,
    "connected_to": [],
    "parent_action": LOOP_ID,
}

data["actions"].extend([condition_action, break_action])

WF.write_text(json.dumps(data, indent=2, ensure_ascii=False))
print(f"[+] added: condition id={COND_ID}, break_loop id={BREAK_ID}")
print(f"[+] loop mode={loop_data['mode']}  expression={loop_data['expression']}  safety_cap={loop_data['number_of_iterations']}")
print(f"[+] total actions: {len(data['actions'])}")
print(f"[+] file updated: {WF}")
