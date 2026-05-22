# OT/ICS SDL Dashboards

Two SentinelOne Singularity Data Lake dashboards for OT/ICS use cases.

| # | Dashboard | File | Use case |
|---|---|---|---|
| 3.2 | Nozomi process-variable anomaly cross-correlation | `nozomi_pv_anomaly.json` | Catches the 2014 German steel-mill ANSSI pattern: HMI/EWS pivot → unauthorized PLC writes → PV deviations across safety zone → blocked shutdown of blast furnace. |
| 3.3 | Crown-jewel / safety-PLC heatmap | `crown_jewel_safety_plc_heatmap.json` | Claroty xDome SRA dashboard pattern; surfaces SIL-3 blast-furnace zone assets, SRA sessions on them, and risk concentration. |

## Data assumptions

Queries target two ingested datasets in SDL:

- **Nozomi Guardian** events parsed into JSON in the `message` field. Expected keys:
  `asset_id`, `asset_name`, `zone`, `protocol`, `function_code`, `src_ip`, `dst_ip`,
  `process_variable`, `value`, `baseline`, `deviation`, `alert_type`, `severity`,
  `threat_name`, `mac_address`, `role` (`HMI` / `EWS` / `PLC` / `SIS`), `vendor`.
- **Claroty xDome** events parsed into JSON in the `message` field. Expected keys:
  `asset_id`, `asset_name`, `zone`, `sil_level`, `criticality`, `risk_score`,
  `vuln_count`, `vuln_severity`, `vendor`, `model`, `firmware`, `last_seen`,
  `sra_session_id`, `sra_user`, `sra_duration_sec`, `business_impact`.

Datasets are distinguished by `dataset == 'nozomi'` and `dataset == 'claroty'`.
If your tenant uses different dataset names or field names, adjust the
`F_NOZOMI` / `F_CLAROTY` filters and `P_*` parse stanzas in `deploy_ot_dashboards.py`.

## Sample data

`sample_data/` ships sanitized synthetic events (RFC 5737 IPs only, no real
customer data):

- `nozomi_sample.jsonl` (~1,400 events) — 24h of baseline + a 90-minute
  ANSSI-2014 steel-mill attack window: `ews-bf-eng-02` (DMZ) issues Modbus
  `WRITE_VAR` / FC 6 / FC 16 against `plc-bf-burner-01`, `plc-bf-tap-02`,
  followed in the same minute by `PROCESS_VARIABLE_ANOMALY` on
  `blast_furnace_temp_c` / `tap_flow_kgs` with growing deviation, periodic
  `STOP_PLC` / `CHANGE_OPERATING_MODE` against `sis-bf-shutdown-01`, and
  `PLC_PROGRAM_DOWNLOAD` / `FIRMWARE_UPDATE` events.
- `claroty_sample.jsonl` (~150 events) — 10 OT assets (4 SIL-3 crown
  jewels in `BLAST_FURNACE` / `SAFETY`), vuln findings, and 60 SRA
  sessions (mix of <1h and >1h) by 6 vendor/contractor users.

Regenerate:
```
python sample_data/generate_samples.py
```

Ingest into SDL:
```
python sample_data/ingest_samples.py
```

## Deploy

Same pattern as the healthcare UEBA dashboard:

```bash
python deploy_ot_dashboards.py
```

It reads the two JSON files in this directory and `PUT`s them to:

- `/dashboards/ot-nozomi-pv-anomaly`
- `/dashboards/ot-crown-jewel-safety-plc`

The script imports `SDLClient` from a sibling `sentinelone-sdl-api/scripts/` repo;
edit `SDL_CLIENT_PATH` at the top of the script to point to your install.

## Detection references

- **3.2** — BSI Lagebericht 2014 §3.3.1 (German steel-mill incident); ANSSI
  "Maîtriser la SSI pour les systèmes industriels"; MITRE ATT&CK for ICS:
  T0836 (Modify Parameter), T0855 (Unauthorized Command Message),
  T0858 (Change Operating Mode), T0831 (Manipulation of Control).
- **3.3** — Claroty xDome SRA module reference; IEC 61511 SIL-3 zone
  classification; MITRE ATT&CK for ICS: T0822 (External Remote Services),
  T0866 (Exploitation of Remote Services).
