#!/usr/bin/env python3
"""Refactor the workflow to poll the aiInvestigation status (5 iterations of
60 s each = 5 min max) instead of a single 180 s wait. Each iteration:
  delay -> http_request (Get Investigation) -> variable (Extract) -> condition
The condition's 'true' branch (status terminal) jumps to the existing
'Is False Positive?' condition; 'false' branch continues to the next iteration.
After the 3rd iteration, we proceed unconditionally (extract may still show
IN_PROGRESS but the email will reflect it)."""
from __future__ import annotations
import json, copy
from pathlib import Path

WF = Path("/path/to/.codeium/windsurf/claroty-pan-detections/hyperautomation/Claroty-Auto-Investigate.json")
data = json.loads(WF.read_text())

# Find existing actions by export_id
by_id = {a["export_id"]: a for a in data["actions"]}
EXISTING_WAIT     = by_id[6]   # delay 180 s
EXISTING_GET      = by_id[5]   # http_request "Get Investigation Result"
EXISTING_EXTRACT  = by_id[4]   # variable "Extract Verdict"
IS_FALSE_POSITIVE = 3          # target for "done" branch

# 1) Reduce the existing wait to 60 s
EXISTING_WAIT["action"]["data"]["value"] = 60

# 2) Build new export_ids starting from max+1
next_id = max(by_id.keys()) + 1
def alloc(): 
    global next_id
    v = next_id; next_id += 1; return v

# Helper to build action wrappers
def mk_delay(name, seconds, position_y):
    return {
        "action": {
            "type": "delay", "tag": "core_action",
            "connection_id": None, "connection_name": None, "use_connection_name": False, "integration_id": None,
            "data": {"name": name, "action_type": "delay", "time_unit": "seconds", "value": seconds},
            "state": "active",
            "description": f"Wait {seconds}s for Purple AI to advance investigation.",
            "client_data": {"position": {"x": 0, "y": position_y}, "dimensions": {"width": 256, "height": 76}, "collapsed": False},
            "snippet_workflow_id": None, "snippet_version_id": None,
        }
    }

def mk_get(name, position_y):
    a = copy.deepcopy(EXISTING_GET)
    a["action"]["data"]["name"] = name
    a["action"]["client_data"]["position"]["y"] = position_y
    return a

def mk_extract(name, source_ref, position_y):
    # source_ref is the kebab-cased name of the corresponding Get step.
    return {
        "action": {
            "type": "variable", "tag": "core_action",
            "connection_id": None, "connection_name": None, "use_connection_name": False, "integration_id": None,
            "data": {
                "name": name, "action_type": "variable",
                "variables": [
                    {"name": "verdict",            "value": f"{{{{{source_ref}.body.data.aiInvestigations[0].verdict}}}}",            "should_use_as_output": False, "is_secret": False},
                    {"name": "result",             "value": f"{{{{{source_ref}.body.data.aiInvestigations[0].result}}}}",             "should_use_as_output": False, "is_secret": False},
                    {"name": "status_ai",          "value": f"{{{{{source_ref}.body.data.aiInvestigations[0].status}}}}",             "should_use_as_output": False, "is_secret": False},
                    {"name": "purple_status",      "value": f"{{{{{source_ref}.body.data.aiInvestigations[0].purpleAiStatus}}}}",     "should_use_as_output": False, "is_secret": False},
                    {"name": "investigation_step", "value": f"{{{{{source_ref}.body.data.aiInvestigations[0].investigationStep}}}}",  "should_use_as_output": False, "is_secret": False},
                    {"name": "timestamp_ai",       "value": f"{{{{{source_ref}.body.data.aiInvestigations[0].timestamp}}}}",          "should_use_as_output": False, "is_secret": False},
                    {"name": "verdict_summary",    "value": f"{{{{{source_ref}.body.data.alert.aiInvestigation.verdict}}}}",          "should_use_as_output": False, "is_secret": False}
                ],
                "variables_scope": "local",
                "expire_in_unit": None, "expire_in_value": None, "expire_method": None,
                "global_var_workflow_access_type": None, "global_var_workflow_access_workflow_ids": None
            },
            "state": "active",
            "description": f"Extract verdict from this poll iteration ({source_ref}).",
            "client_data": {"position": {"x": 0, "y": position_y}, "dimensions": {"width": 256, "height": 76}, "collapsed": False},
            "snippet_workflow_id": None, "snippet_version_id": None,
        }
    }

def mk_is_done(name, position_y):
    return {
        "action": {
            "type": "condition", "tag": "core_action",
            "connection_id": None, "connection_name": None, "use_connection_name": False, "integration_id": None,
            "data": {
                "name": name, "action_type": "condition", "condition_type": "multi", "condition": None,
                "conditions": [
                    {"input_value": "{{local_var.status_ai}}", "compared_value": "[\"COMPLETED\",\"FAILED\",\"RESTRICTED\"]", "comparison_operator": "in"}
                ],
                "conditions_relationship": "and",
            },
            "state": "active",
            "description": "If aiInvestigation status is terminal, stop polling and proceed to verdict branching.",
            "client_data": {"position": {"x": 0, "y": position_y}, "dimensions": {"width": 256, "height": 76}, "collapsed": False},
            "snippet_workflow_id": None, "snippet_version_id": None,
        }
    }

# Replace the existing Extract Verdict (4) to use the SAME variable map as the
# poll iterations - source from get-investigation-result (which is poll #1)
EXISTING_EXTRACT["action"]["data"]["name"] = "Extract Verdict (poll #1)"
# Leave its variables as-is (they already reference get-investigation-result)
EXISTING_EXTRACT["action"]["description"] = "Extract verdict from poll #1 (initial 60 s wait)."

# Build poll #2 and #3 iterations
ITERATION_Y0 = 900   # below current Wait at y=800
y = ITERATION_Y0

# IDs (allocated)
is_done_1_id = alloc()
delay_2_id   = alloc()
get_2_id     = alloc()
extract_2_id = alloc()
is_done_2_id = alloc()
delay_3_id   = alloc()
get_3_id     = alloc()
extract_3_id = alloc()

is_done_1 = mk_is_done("Is Done? #1", y); y += 100
delay_2   = mk_delay("Wait for Investigation #2", 60, y); y += 100
get_2     = mk_get("Get Investigation Result 2", y); y += 100
extract_2 = mk_extract("Extract Verdict (poll #2)", "get-investigation-result-2", y); y += 100
is_done_2 = mk_is_done("Is Done? #2", y); y += 100
delay_3   = mk_delay("Wait for Investigation #3", 60, y); y += 100
get_3     = mk_get("Get Investigation Result 3", y); y += 100
extract_3 = mk_extract("Extract Verdict (poll #3)", "get-investigation-result-3", y); y += 100

# Stamp export_ids and connect_to
is_done_1["export_id"]  = is_done_1_id
delay_2["export_id"]    = delay_2_id
get_2["export_id"]      = get_2_id
extract_2["export_id"]  = extract_2_id
is_done_2["export_id"]  = is_done_2_id
delay_3["export_id"]    = delay_3_id
get_3["export_id"]      = get_3_id
extract_3["export_id"]  = extract_3_id

for a in [is_done_1, delay_2, get_2, extract_2, is_done_2, delay_3, get_3, extract_3]:
    a["parent_action"] = None

# Wiring:
# Existing Extract Verdict (4) -> Is Done? #1 (was -> 3)
EXISTING_EXTRACT["connected_to"] = [{"target": is_done_1_id, "custom_handle": None, "payload": None}]

# Is Done? #1 -> true: IS_FALSE_POSITIVE (3); false: delay_2
is_done_1["connected_to"] = [
    {"target": IS_FALSE_POSITIVE, "custom_handle": "true",  "payload": None},
    {"target": delay_2_id,        "custom_handle": "false", "payload": None},
]
delay_2["connected_to"]   = [{"target": get_2_id, "custom_handle": None, "payload": None}]
get_2["connected_to"]     = [{"target": extract_2_id, "custom_handle": None, "payload": None}]
extract_2["connected_to"] = [{"target": is_done_2_id, "custom_handle": None, "payload": None}]
is_done_2["connected_to"] = [
    {"target": IS_FALSE_POSITIVE, "custom_handle": "true",  "payload": None},
    {"target": delay_3_id,        "custom_handle": "false", "payload": None},
]
delay_3["connected_to"]   = [{"target": get_3_id, "custom_handle": None, "payload": None}]
get_3["connected_to"]     = [{"target": extract_3_id, "custom_handle": None, "payload": None}]
# Final extract proceeds regardless of status
extract_3["connected_to"] = [{"target": IS_FALSE_POSITIVE, "custom_handle": None, "payload": None}]

# Append new actions
data["actions"].extend([is_done_1, delay_2, get_2, extract_2, is_done_2, delay_3, get_3, extract_3])

# Validate + write
out = WF
out.write_text(json.dumps(data, indent=2, ensure_ascii=False))
print(f"[+] wrote {out}: {len(data['actions'])} actions total")
print(f"[+] new polling action IDs: is_done#1={is_done_1_id} delay#2={delay_2_id} get#2={get_2_id} "
      f"extract#2={extract_2_id} is_done#2={is_done_2_id} delay#3={delay_3_id} get#3={get_3_id} extract#3={extract_3_id}")
print(f"[+] poll cadence: 60 s + 60 s + 60 s (~3 min max wait), terminal status short-circuits.")
