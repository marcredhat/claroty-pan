# Sanitized package

The following tenant-specific values have been redacted and replaced with
placeholders. Fill them in for your own tenant before running:

| Placeholder | What to provide |
|---|---|
| `REPLACE_WITH_TOKEN` (in `config.json.example`) | A SentinelOne SDL or mgmt-console API token / JWT |
| `<your-region>.sentinelone.net` | Your tenant's mgmt console base URL (e.g. `usea1-prod.sentinelone.net`) |
| `<YOUR_SITE_ID>` | Numeric site ID from the console |
| `<YOUR_TENANT_ID>` | Numeric tenant/account ID |
| `<YOUR_CONSOLE_VERSION>` (inside `hyperautomation/Claroty-Auto-Investigate.json`) | Release string from `GET /web/api/v2.1/system/info` -> `release` (e.g. `S-26.1.6`) |
| `<YOUR_INTEGRATION_ID>` | Hyperautomation HTTP integration UUID for the GraphQL endpoint |
| `<YOUR_CONNECTION_ID>` | Connection UUID bound to that integration |
| `<YOUR_DEPLOYMENT_ID>` | Deployment id from your token claims |

Two empty config templates are provided:

- `config.json.example` (SDL keys + console API token, used by everything in `scripts/`)
- `hyperautomation/config.json.example` (mgmt console base URL + token, used by `import_workflow.py` etc.)

Copy each to `config.json` (drop the `.example` suffix) in the same folder and
fill in real values. `config.json` is intentionally gitignored / not shipped.
