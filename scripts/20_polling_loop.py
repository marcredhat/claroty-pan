#!/usr/bin/env python3
"""Replace the linear 3-iteration polling block with a single Loop action
(dynamic mode iterating over a 10-element array). Inside the loop: delay 30 s,
HTTP get investigation, variable extract. The loop runs at most 10 iterations
(~5 min) sequentially; each iteration overwrites the same local_var.* so the
LAST iteration's poll result is what gets used by 'Is False Positive?'.

This is the tenant's only verified loop mode (no while/static observed across
90 loop samples on this tenant). For more efficiency at scale we could add an
inner condition that early-terminates the iteration path when status is
terminal - but 30 s polling over 5 min is cheap enough as-is."""
from __future__ import annotations
import json, copy
from pathlib import Path

WF = Path("/path/to/.codeium/windsurf/claroty-pan-detections/hyperautomation/Claroty-Auto-Investigate.json")
data = json.loads(WF.read_text())

# Locate helpers
def find_by_name(substr):
    for a in data["actions"]:
        d = (a.get("action") or {}).get("data") or {}
        if substr in (d.get("name") or ""):
            return a
    return None

email_started   = find_by_name("Email")          # Email Investigation Started (target after trigger ai inv)
trigger_ai_inv  = find_by_name("Trigger AI Investigation")
get1            = find_by_name("Get Investigation Result")  # picks up first match "Get Investigation Result"
extract1        = find_by_name("Extract Verdict (poll #1)")
is_fp           = find_by_name("Is False Positive?")
assert all([trigger_ai_inv, get1, extract1, is_fp])
IS_FP_ID = is_fp["export_id"]
print(f"[+] anchor IDs: trigger_ai_inv={trigger_ai_inv['export_id']}  get1={get1['export_id']}  "
      f"extract1={extract1['export_id']}  is_fp={IS_FP_ID}")

# Step 1: identify all polling actions added by 19_inject_polling.py and remove them.
POLL_ACTION_NAMES = {
    "Wait for Investigation",        # original delay (we'll rebuild)
    "Get Investigation Result",      # poll #1 get
    "Extract Verdict (poll #1)",
    "Is Done? #1",
    "Wait for Investigation #2",
    "Get Investigation Result 2",
    "Extract Verdict (poll #2)",
    "Is Done? #2",
    "Wait for Investigation #3",
    "Get Investigation Result 3",
    "Extract Verdict (poll #3)",
}

# Save the "Get Investigation Result" template (we'll reuse for the loop body)
GET_TEMPLATE     = copy.deepcopy(get1)
EXTRACT_TEMPLATE = copy.deepcopy(extract1)

# Drop the old polling actions
before = len(data["actions"])
data["actions"] = [
    a for a in data["actions"]
    if ((a.get("action") or {}).get("data") or {}).get("name") not in POLL_ACTION_NAMES
]
print(f"[+] stripped {before - len(data['actions'])} legacy polling actions")

# Find the action that previously fed the polling block (the email "Investigation Started").
# It now has a dangling connected_to pointing to the old Wait id - we'll repoint it to the new loop.
email_started_name = None
for a in data["actions"]:
    d = (a.get("action") or {}).get("data") or {}
    n = d.get("name") or ""
    if "Email" in n and "Investigation Started" in n:
        email_started_name = n
        email_started_act  = a
        break
assert email_started_name, "Email Investigation Started step missing"

# Step 2: allocate new export_ids for the loop and inner actions.
existing_ids = {a["export_id"] for a in data["actions"]}
next_id = max(existing_ids) + 1
def alloc():
    global next_id; v = next_id; next_id += 1; return v

LOOP_ID    = alloc()
DELAY_ID   = alloc()
GET_ID     = alloc()
EXTRACT_ID = alloc()

# Step 3: build the loop action.
loop_action = {
    "action": {
        "type": "loop",
        "tag": "core_action",
        "connection_id": None, "connection_name": None, "use_connection_name": False, "integration_id": None,
        "data": {
            "name": "Poll Investigation (up to 10 x 30s = 5 min)",
            "action_type": "loop",
            "loop_type": "dynamic",
            "number_of_iterations": "10",
            "object_to_iterate": "[1,2,3,4,5,6,7,8,9,10]",
            "is_parallel": False,
        },
        "state": "active",
        "description": "Poll aiInvestigations every 30 s for up to 5 min. Each iteration overwrites local_var.verdict/result/status_ai so the final iteration's value is what reaches the 'Is False Positive?' branch.",
        "client_data": {"position": {"x": 0, "y": 800}, "dimensions": {"width": 768, "height": 320}, "collapsed": False},
        "snippet_workflow_id": None, "snippet_version_id": None,
    },
    "export_id": LOOP_ID,
    "connected_to": [
        {"target": IS_FP_ID,  "custom_handle": None,    "payload": None},   # after the loop
        {"target": DELAY_ID,  "custom_handle": "inner", "payload": None},   # first inner step
    ],
    "parent_action": None,
}

# Step 4: build inner: delay 30s -> Get Investigation -> Extract Verdict.
inner_delay = {
    "action": {
        "type": "delay", "tag": "core_action",
        "connection_id": None, "connection_name": None, "use_connection_name": False, "integration_id": None,
        "data": {"name": "Poll Delay 30s", "action_type": "delay", "time_unit": "seconds", "value": 30},
        "state": "active",
        "description": "30 s between polls inside the loop.",
        "client_data": {"position": {"x": -200, "y": 900}, "dimensions": {"width": 256, "height": 76}, "collapsed": False},
        "snippet_workflow_id": None, "snippet_version_id": None,
    },
    "export_id": DELAY_ID,
    "connected_to": [{"target": GET_ID, "custom_handle": None, "payload": None}],
    "parent_action": LOOP_ID,
}

# Reuse the existing Get Investigation Result template (same connection/payload/etc.)
inner_get = copy.deepcopy(GET_TEMPLATE)
inner_get["export_id"] = GET_ID
inner_get["parent_action"] = LOOP_ID
inner_get["connected_to"] = [{"target": EXTRACT_ID, "custom_handle": None, "payload": None}]
inner_get["action"]["data"]["name"] = "Get Investigation Result (loop)"
inner_get["action"]["client_data"] = {
    "position": {"x": 0, "y": 1000}, "dimensions": {"width": 256, "height": 100}, "collapsed": False
}

# Build extract referencing the loop-internal get step by its kebab-case name.
extract_action = {
    "action": {
        "type": "variable", "tag": "core_action",
        "connection_id": None, "connection_name": None, "use_connection_name": False, "integration_id": None,
        "data": {
            "name": "Extract Verdict (loop)",
            "action_type": "variable",
            "variables": [
                {"name": "verdict",            "value": "{{get-investigation-result-loop.body.data.aiInvestigations[0].verdict}}",            "should_use_as_output": False, "is_secret": False},
                {"name": "result",             "value": "{{get-investigation-result-loop.body.data.aiInvestigations[0].result}}",             "should_use_as_output": False, "is_secret": False},
                {"name": "status_ai",          "value": "{{get-investigation-result-loop.body.data.aiInvestigations[0].status}}",             "should_use_as_output": False, "is_secret": False},
                {"name": "purple_status",      "value": "{{get-investigation-result-loop.body.data.aiInvestigations[0].purpleAiStatus}}",     "should_use_as_output": False, "is_secret": False},
                {"name": "investigation_step", "value": "{{get-investigation-result-loop.body.data.aiInvestigations[0].investigationStep}}",  "should_use_as_output": False, "is_secret": False},
                {"name": "timestamp_ai",       "value": "{{get-investigation-result-loop.body.data.aiInvestigations[0].timestamp}}",          "should_use_as_output": False, "is_secret": False},
                {"name": "verdict_summary",    "value": "{{get-investigation-result-loop.body.data.alert.aiInvestigation.verdict}}",          "should_use_as_output": False, "is_secret": False}
            ],
            "variables_scope": "local",
            "expire_in_unit": None, "expire_in_value": None, "expire_method": None,
            "global_var_workflow_access_type": None, "global_var_workflow_access_workflow_ids": None,
        },
        "state": "active",
        "description": "Overwrite local_var.* with this iteration's poll result.",
        "client_data": {"position": {"x": 200, "y": 1100}, "dimensions": {"width": 256, "height": 76}, "collapsed": False},
        "snippet_workflow_id": None, "snippet_version_id": None,
    },
    "export_id": EXTRACT_ID,
    "connected_to": [],   # tail of the inner chain
    "parent_action": LOOP_ID,
}

# Step 5: rewire email_started -> loop, and append new actions.
email_started_act["connected_to"] = [{"target": LOOP_ID, "custom_handle": None, "payload": None}]

data["actions"].extend([loop_action, inner_delay, inner_get, extract_action])

# Step 6: write back.
WF.write_text(json.dumps(data, indent=2, ensure_ascii=False))
print(f"[+] wrote {WF}")
print(f"[+] total actions: {len(data['actions'])}")
print(f"[+] loop id={LOOP_ID} (inner: delay={DELAY_ID} get={GET_ID} extract={EXTRACT_ID})")
print(f"[+] poll cadence: 10 x 30 s sequential = 5 min max")
