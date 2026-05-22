# Claroty x Palo Alto Drift detections

Each `.pq` file is a self-contained SentinelOne PowerQuery alert body.
`claroty_pan_drift_rules.json` bundles them all in the format consumed by
the `librarydetections` repo loader.

| Code | Severity | Title |
|---|---|---|
| D1 | High | OT critical asset has wrong or missing Palo Alto EDL/DAG |
| D2 | Medium | OT device reclassified in Claroty but Palo Alto tagging is stale |
| D3 | High | Newly discovered or unmanaged OT asset crossing zones |
| D4 | Critical | High-risk Claroty asset communicating outside its approved zone |
| D5 | Medium | Decommissioned Claroty asset still resolved by an active EDL/DAG |

Prerequisite lookup: `claroty_assets` (build with `savelookup`).