# 🛡️ MCP Boss — Autonomous Security Operations Server

**91 tools.** One endpoint. Talk to your entire Google security stack in plain English.

MCP Boss gives any AI model (Gemini, Claude, GPT) full access to SecOps, SCC, GTI, Cloud Logging, SOAR, BigQuery, IAM, and cross-platform containment — through the [Model Context Protocol](https://modelcontextprotocol.io).

---

## Quick Start

### One-line install:
```bash
curl -sL https://raw.githubusercontent.com/dnehoda-source/MCP-Boss/main/setup.sh | bash -s -- \
  --project your-project-id \
  --customer your-secops-customer-id \
  --gti-key your-vt-api-key
```

### Or deploy from Google Cloud Shell:
[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/dnehoda-source/MCP-Boss.git&shellonly=true&cloudshell_workspace=MCP-Boss)

After Cloud Shell opens, run in the terminal:
```bash
chmod +x setup.sh && ./setup.sh
```
The wizard will walk you through project ID, customer ID, and deploy everything.

### Or step by step:
```bash
git clone https://github.com/dnehoda-source/MCP-Boss.git
cd MCP-Boss && ./setup.sh
```

The setup wizard handles everything: APIs, service account, IAM roles, container build, Cloud Run deploy, and verification.

---

## What It Does

You ask a question → Gemini picks the right tools → executes them → chains results across multiple sources → gives you a report. No clicking through UIs, no writing API calls, no switching consoles.

**Example:** *"Hunt for APT28 across all sources"* →
1. Looks up APT28 threat intel via GTI/VirusTotal
2. Searches your SIEM for matching IOCs
3. Checks SCC for exploitable vulnerabilities matching their TTPs
4. Correlates findings across all sources
5. Produces an executive summary with recommended actions

All automatic, up to 20 chained tool calls in a single request.

---

## Benchmark

First benchmark run on a live Cloud Run deployment (2026-04-22, gemini-2.5-flash, 6 scenarios):

| Metric | Value |
|---|---|
| correct_verdict_pct | 83.3% (5/6 scenarios) |
| correct_containment_pct | 13.9% |
| destructive_fp_rate_pct | **0.0%** |
| median_alert_to_containment_s | 60.87 |

Full scorecard, scenarios, and raw tool traces live under `eval_harness/` (`scorecard-2026-04-22.md`, `results.json`). Rerun any time with `./eval_harness/run.sh`. Nobody else in this category publishes these numbers credibly; that is the point.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     USER INTERFACES                          │
│   Web UI  ·  Gemini CLI  ·  Claude Desktop  ·  Mobile App   │
└──────────────────────┬───────────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          │ /api/chat (Web UI)      │  ← Multi-turn orchestration
          │ /mcp     (Gemini CLI)   │  ← Streamable HTTP
          │ /sse     (Claude/MCP)   │  ← SSE transport
          └────────────┬────────────┘
                       │
┌──────────────────────▼───────────────────────────────────────┐
│              MCP Boss Server (Cloud Run)                      │
│              89 Tools · Python · FastMCP · Serverless         │
│                                                              │
│  🔍 Discovery    🧠 Intel       🛡️ Detection    📂 SOAR     │
│  ├─ SCC          ├─ GTI/VT      ├─ YARA-L       ├─ Cases    │
│  ├─ Cloud Log    ├─ Malware     ├─ Rules         ├─ Playbooks│
│  ├─ UDM Search   ├─ Actors      ├─ Alerts        ├─ Actions  │
│  ├─ Ingestion    └─ Vertex AI   └─ Data Tables   └─ Metrics  │
│                                                              │
│  📧 Containment  ☁️ Cloud        📊 Analytics                │
│  ├─ O365 Purge   ├─ AWS Keys    ├─ BigQuery                 │
│  ├─ Okta         ├─ GCP SA      ├─ MTTx Metrics             │
│  ├─ Azure AD     ├─ STS Revoke  ├─ Audit Logs               │
│  └─ CrowdStrike  └─ IAM Review  └─ Cloud Monitoring         │
└──────────────────────────────────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          │  Google Cloud APIs       │
          │  Chronicle · SCC · GTI   │
          │  Vertex AI · BigQuery    │
          │  Cloud Logging · IAM     │
          │  Cloud Monitoring        │
          └─────────────────────────┘
```

**Zero embedded secrets.** All Google API authentication uses Workload Identity Federation (Application Default Credentials). The Cloud Run service account authenticates automatically. Third-party containment APIs (Okta, AWS, Azure AD, CrowdStrike, O365) use environment variables backed by Secret Manager.

---

## Security

MCP Boss handles sensitive security data. Here's how to lock it down.

> **Auth-off equals policy-off.** When `OAUTH_CLIENT_ID` is unset, the built-in auth middleware no-ops and the approval role check in `/api/approvals/*/decide` falls back to an allow-all path so dev workflows keep working. This means a deployment without `OAUTH_CLIENT_ID` has no enforcement: anyone with network reach can approve any destructive tool call. Any non-dev deploy MUST set `OAUTH_CLIENT_ID` (and populate a `ROLE_MAP_JSON` or `ROLE_MAP_PATH`). See `auth_middleware.py` and `deploy/multi_tenant/README.md`.
>
> Boot will refuse to start if `LOCAL_DEV_ALL_ROLES=1` is set without `OAUTH_CLIENT_ID` unless you also set `MCP_BOSS_ENV=dev`. That combo grants every caller every approver role.
>
> MCP transport (stdio/SSE) session tools (`create_session`, `get_session`, `update_session`, `add_note`) still run under a single tenant because those transports carry no HTTP identity. Restrict MCP transport access at the infra layer (Cloud Run IAM invoker on `/mcp` and `/sse`).

### Option 1: IAM Authentication (Recommended)

Remove public access and require Google Cloud IAM authentication:

```bash
# Remove unauthenticated access
gcloud run services remove-iam-policy-binding mcp-boss \
  --member="allUsers" \
  --role="roles/run.invoker" \
  --project=$PROJECT_ID \
  --region=us-central1

# Grant access to specific users only
gcloud run services add-iam-policy-binding mcp-boss \
  --member="user:analyst@yourcompany.com" \
  --role="roles/run.invoker" \
  --project=$PROJECT_ID \
  --region=us-central1

# Grant access to a Google Group (for SOC team)
gcloud run services add-iam-policy-binding mcp-boss \
  --member="group:soc-team@yourcompany.com" \
  --role="roles/run.invoker" \
  --project=$PROJECT_ID \
  --region=us-central1
```

**How to access after locking down:**

```bash
# From browser — use Cloud Run Proxy:
gcloud run services proxy mcp-boss --project=$PROJECT_ID --region=us-central1
# Opens http://localhost:8080 → authenticated tunnel to your service

# From curl/API:
TOKEN=$(gcloud auth print-identity-token)
curl -H "Authorization: Bearer $TOKEN" https://YOUR-SERVICE-URL/health

# From Gemini CLI:
TOKEN=$(gcloud auth print-identity-token)
gemini --tool-endpoint https://YOUR-SERVICE-URL/mcp --headers "Authorization=Bearer $TOKEN"
```

### Option 2: VPC-Only (Internal Network)

Restrict to your VPC — no public internet access at all:

```bash
gcloud run services update mcp-boss \
  --ingress=internal \
  --project=$PROJECT_ID \
  --region=us-central1
```

Only accessible from within your VPC, VPN, or Cloud Interconnect.

**How to access:**
```bash
# From your local machine via Cloud Run Proxy (tunnels through IAM):
gcloud run services proxy mcp-boss --project=$PROJECT_ID --region=us-central1
# Opens http://localhost:8080 locally

# Or from a GCE VM / GKE pod inside the VPC:
curl https://YOUR-SERVICE-URL/health
```

### Option 3: IAP (Identity-Aware Proxy)

Put Cloud IAP in front for browser-based SSO with your corporate identity provider:

```bash
# Enable IAP on the Cloud Run service
gcloud iap web enable \
  --resource-type=cloud-run \
  --service=mcp-boss \
  --project=$PROJECT_ID

# Grant access to your SOC team
gcloud iap web add-iam-policy-binding \
  --resource-type=cloud-run \
  --service=mcp-boss \
  --member="group:soc-team@yourcompany.com" \
  --role="roles/iap.httpsResourceAccessor" \
  --project=$PROJECT_ID
```

Users get a Google login prompt in the browser before reaching the Web UI. No code changes needed — IAP handles everything.

**How to access:** Just open the URL in a browser. IAP shows a Google login page. After sign-in, you're through to the Web UI.

### Option 4: API Key Header

For quick protection, set an API key environment variable and validate in requests:

```bash
gcloud run services update mcp-boss \
  --set-env-vars="MCP_BOSS_API_KEY=your-secret-key-here" \
  --project=$PROJECT_ID \
  --region=us-central1
```

**How to access:**
```bash
# curl:
curl -H "X-API-Key: your-secret-key-here" https://YOUR-SERVICE-URL/health

# Gemini CLI:
gemini --tool-endpoint https://YOUR-SERVICE-URL/mcp --headers "X-API-Key=your-secret-key-here"

# Web UI: Add ?key=your-secret-key-here to the URL
# Or the Web UI will prompt for it on first load
```

The server validates this automatically when `MCP_BOSS_API_KEY` is set.

### Security Best Practices

| Practice | How |
|----------|-----|
| **No public access** | Remove `allUsers` invoker binding |
| **Least privilege SA** | Use dedicated `mcp-boss` service account, not default compute SA |
| **Secret Manager** | Store API keys (GTI, Okta, AWS, etc.) in Secret Manager, not env vars |
| **Audit logging** | Cloud Run request logs are automatic; enable Data Access audit logs |
| **VPC SC** | Place the project in a VPC Service Controls perimeter |
| **Containment approval** | Built in: see "Authentication & Approvals" below |
| **Network** | Use `--ingress=internal` + Cloud VPN/Interconnect for production |

---

## Authentication & Approvals

Application-level controls that sit on top of Cloud Run IAM. All of them are off by default; opt in with env vars.

### Authentication (Google ID tokens)

Set `OAUTH_CLIENT_ID` and the server rejects any request without a valid Google OIDC ID token whose `aud` matches.

| Variable | Purpose |
|---|---|
| `OAUTH_CLIENT_ID` | Primary audience. Usually your browser-flow OAuth 2.0 client ID. |
| `OAUTH_ADDITIONAL_AUDIENCES` | Comma-separated extra accepted audiences. Add the service URL or `32555940559.apps.googleusercontent.com` (gcloud default client) for server-to-server CI calls. |
| `ALLOWED_EMAILS` | Optional comma-separated allowlist. If set, an authenticated email not on the list is rejected. |
| `AUTH_EXEMPT_PATHS` | Comma-separated path prefixes that bypass auth (default `/health,/static`). |

When `OAUTH_CLIENT_ID` is unset the middleware is a no-op: auth is disabled, principal is `local`, every role check passes. Do not ship this configuration outside local dev. The server refuses to start if `LOCAL_DEV_ALL_ROLES=1` is set without either `OAUTH_CLIENT_ID` or `MCP_BOSS_ENV=dev`.

### Role mapping and approver groups

`policy_and_approvals/policies.yaml` maps each destructive tool (host isolation, key revocation, email purge, etc.) to one or more approver role names. To authorise a caller, map their email to a role set.

| Variable | Format |
|---|---|
| `ROLE_MAP_JSON` | Inline JSON: `{"alice@co.com":["security-oncall"], "@co.com":["soc-manager"]}` |
| `ROLE_MAP_PATH` | Path to a YAML file: `roles: {alice@co.com: [security-oncall]}` |

Approver role names recognised by the default `policies.yaml`: `security-oncall`, `soc-manager`, `identity-team`, `cloud-platform`, `detection-engineering`, `legal`, `security-leadership`.

### Approval workflow

1. Orchestrator wants to invoke a gated tool (e.g. `isolate_crowdstrike_host`).
2. Policy gate checks `policies.yaml`. If `require_approval`, it freezes the tool call as an `ApprovalRequest`.
3. The approval is broadcast via any configured channel: `/api/approvals` (web UI), Google Chat card (`GOOGLE_CHAT_WEBHOOK_URL`), generic webhook (`APPROVAL_WEBHOOK_URL`).
4. An approver hits `POST /api/approvals/{id}/decide` with `approve` / `deny`. The server 403s unless the authenticated caller's roles intersect the rule's `approver_groups`. `decided_by` is rebound to the authenticated email so the audit trail cannot be spoofed.
5. On approve, the tool executes. Every state transition lands in the hash-chained audit log.

Verify the chain any time with `GET /api/audit/verify`:

```json
{"chain_intact": true, "broken_at_seq": null, "audit_path": "/var/log/mcp-boss/audit.jsonl"}
```

### Tenant isolation

`SessionMemory` is keyed by (authenticated principal, session_id). Two users on the same Cloud Run instance cannot read each other's investigation history even if they guess session IDs. MCP transport session tools (stdio / SSE) use a distinct `mcp-transport` namespace; gate that transport at the infra layer (Cloud Run IAM invoker on `/mcp` and `/sse`).

### Output redaction (DLP)

Set `ENABLE_OUTPUT_REDACTION=1` and every tool result is scanned before it flows back to the LLM or the API response. Luhn-checked CC numbers, SSN-looking strings (with IP/date guards), PEM private keys, AWS access keys, JWTs, and labelled API keys (GTI, Okta, CrowdStrike, Azure AD, O365, `api_key`, `bearer_token`, `client_secret`, `access_token`) are replaced with `[REDACTED:<type>]`. The audit log records the un-redacted content; only what crosses the tool-to-LLM boundary is sanitised.

---

## Operations

### Daily use

- **Web UI** — browse to the Cloud Run URL, sign in with Google. Paste an alert or ask a question.
- **Gemini CLI** — `gemini --tool-endpoint https://YOUR-URL/mcp --headers "Authorization=Bearer $(gcloud auth print-identity-token)"`.
- **Claude Desktop** — add the `/sse` URL to `claude_desktop_config.json` (see the Connect section).

Every request produces a chat transcript (in the web UI), a full tool trace (in Cloud Logging), and an audit record for any gated tool call.

### Benchmark / regression

```bash
export MCP_URL=https://YOUR-SERVICE-URL
export MCP_ID_TOKEN=$(gcloud auth print-identity-token)
./eval_harness/run.sh
```

Produces `scorecard.md` (headline numbers) and `results.json` (raw tool traces per scenario). Wire this into CI and fail the build if `destructive_fp_rate_pct > 0` or verdict accuracy drops.

### Audit log export

Records are JSONL at `$MCP_BOSS_AUDIT_PATH` (default `/var/log/mcp-boss/audit.jsonl`, falls back to `~/.mcp-boss/audit.jsonl`) and mirrored to Cloud Logging under log name `mcp-boss-audit`. Point a BigQuery sink at the Cloud Logging stream for long-term retention and SIEM ingest.

### Multi-tenant install

`deploy/multi_tenant/install.sh` runs `terraform apply` with Artifact Registry, Secret Manager stubs, Cloud Run v2, and IAM bindings in one command. Pass `--oauth-client-id`, `--allowed-emails`, `--role-map-json`, and `--enable-redaction` to set the full auth config at deploy time.

---

## Manual Setup Guide

If you prefer to set things up manually instead of using `setup.sh`:

### Prerequisites

- Google Cloud project with billing enabled
- `gcloud` CLI installed and authenticated
- Chronicle / SecOps instance with a customer ID

### Step 1: Enable APIs

```bash
PROJECT_ID=your-project-id

gcloud services enable \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    chronicle.googleapis.com \
    securitycenter.googleapis.com \
    aiplatform.googleapis.com \
    logging.googleapis.com \
    bigquery.googleapis.com \
    monitoring.googleapis.com \
    iam.googleapis.com \
    cloudresourcemanager.googleapis.com \
    --project=$PROJECT_ID
```

### Step 2: Create Service Account & Grant IAM Roles

```bash
SA_NAME=mcp-boss
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# Create the service account
gcloud iam service-accounts create $SA_NAME \
  --display-name="MCP Boss Service Account" \
  --project=$PROJECT_ID

# Grant required roles
ROLES=(
  roles/chronicle.admin
  roles/securitycenter.findingsViewer
  roles/aiplatform.user
  roles/logging.viewer
  roles/bigquery.dataViewer
  roles/bigquery.jobUser
  roles/monitoring.viewer
  roles/iam.securityReviewer
)

for ROLE in "${ROLES[@]}"; do
  gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="$ROLE" --quiet
done
```

#### IAM Roles Reference

| Role | What it enables | Required? |
|------|----------------|-----------|
| `roles/chronicle.admin` | UDM search, rules, cases, detections, data tables, feeds, parsers, alerts | ✅ Yes |
| `roles/securitycenter.findingsViewer` | SCC vulnerability findings, misconfigurations | ✅ Yes |
| `roles/aiplatform.user` | Vertex AI Gemini — threat analysis, investigation reports | ✅ Yes |
| `roles/logging.viewer` | Cloud Audit Log queries | ✅ Yes |
| `roles/bigquery.dataViewer` | BigQuery security data lake reads | ✅ Yes |
| `roles/bigquery.jobUser` | BigQuery SQL execution | ✅ Yes |
| `roles/monitoring.viewer` | Cloud Monitoring — ingestion bandwidth stats | ✅ Yes |
| `roles/iam.securityReviewer` | IAM policy and service account auditing | ✅ Yes |
| `roles/iam.serviceAccountKeyAdmin` | GCP containment: revoke SA keys | ⚙️ Optional |
| `roles/storage.admin` | Cloud Build deployment access | ⚙️ Deploy only |

### Step 3: Build & Deploy

```bash
# Build
gcloud builds submit \
  --project=$PROJECT_ID \
  --tag gcr.io/$PROJECT_ID/mcp-boss:latest

# Deploy
gcloud run deploy mcp-boss \
  --image gcr.io/$PROJECT_ID/mcp-boss:latest \
  --project=$PROJECT_ID \
  --region=us-central1 \
  --platform=managed \
  --service-account=$SA_EMAIL \
  --allow-unauthenticated \
  --memory=512Mi \
  --timeout=300 \
  --set-env-vars="SECOPS_PROJECT_ID=$PROJECT_ID,SECOPS_CUSTOMER_ID=YOUR_CUSTOMER_ID,SECOPS_REGION=us,GTI_API_KEY=YOUR_VT_KEY"
```

### Step 4: Verify

```bash
curl https://YOUR-SERVICE-URL/health
# {"status":"healthy","tools":89,...}
```

### Step 5: Connect

**Web UI:** Open your Cloud Run URL in a browser.

**Gemini CLI:**
```bash
gemini --tool-endpoint https://YOUR-SERVICE-URL/mcp
```

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "mcp-boss": {
      "url": "https://YOUR-SERVICE-URL/sse"
    }
  }
}
```

---

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `SECOPS_PROJECT_ID` | Your GCP project ID |
| `SECOPS_CUSTOMER_ID` | Chronicle/SecOps customer ID (from Chronicle settings) |
| `SECOPS_REGION` | `us`, `eu`, or `asia` |

### Recommended

| Variable | Description |
|----------|-------------|
| `GTI_API_KEY` | VirusTotal / Google Threat Intelligence API key |

### Authentication

| Variable | Description |
|----------|-------------|
| `OAUTH_CLIENT_ID` | Google OAuth 2.0 client ID. When set, every request must present a valid ID token whose `aud` matches. Unset = auth disabled (dev only). |
| `OAUTH_ADDITIONAL_AUDIENCES` | Comma-separated extra accepted audiences. Add the service URL or `32555940559.apps.googleusercontent.com` for server-to-server / CI. |
| `ALLOWED_EMAILS` | Comma-separated allowlist of authenticated emails. If set, other emails are rejected. |
| `ROLE_MAP_JSON` | Inline JSON mapping email or `@domain` to approver role lists. |
| `ROLE_MAP_PATH` | YAML file with `roles:` block. Same shape as `ROLE_MAP_JSON`. |
| `AUTH_EXEMPT_PATHS` | Path prefixes that bypass auth (default `/health,/static`). |
| `LOCAL_DEV_ALL_ROLES` | `1` grants every caller every approver role. Requires `MCP_BOSS_ENV=dev`; otherwise server refuses to start. |
| `MCP_BOSS_ENV` | Operator declaration. Set to `dev` on a dev machine to allow `LOCAL_DEV_ALL_ROLES=1`. |

### Operations

| Variable | Description |
|----------|-------------|
| `ENABLE_OUTPUT_REDACTION` | `1` enables DLP pass on tool results before they flow to the LLM. Off by default. |
| `MCP_BOSS_AUDIT_PATH` | JSONL audit log path (default `/var/log/mcp-boss/audit.jsonl`, falls back to `~/.mcp-boss/audit.jsonl`). |
| `GOOGLE_CHAT_WEBHOOK_URL` | Google Chat webhook for approval cards. |
| `APPROVAL_WEBHOOK_URL` | Generic webhook for approval notifications. |
| `PUBLIC_BASE_URL` | Public URL used when building links in approval notifications. |
| `GEMINI_MODEL` | Gemini model for orchestration (default `gemini-2.5-flash`). |

### Optional — Third-Party Containment

| Variable | Description |
|----------|-------------|
| `O365_TENANT_ID`, `O365_CLIENT_ID`, `O365_CLIENT_SECRET` | Microsoft Graph — email purge |
| `OKTA_DOMAIN`, `OKTA_API_TOKEN` | Okta — user suspension |
| `AZURE_AD_TENANT_ID`, `AZURE_AD_CLIENT_ID`, `AZURE_AD_CLIENT_SECRET` | Azure AD — session revocation |
| `SOAR_AWS_KEY`, `SOAR_AWS_SECRET` | AWS — IAM key revocation |
| `CROWDSTRIKE_CLIENT_ID`, `CROWDSTRIKE_CLIENT_SECRET` | CrowdStrike — host isolation |

Any sensitive env var accepts `sm://PROJECT/SECRET_NAME` in place of a plaintext value. The `secrets_resolver` module transparently fetches the latest version from Google Secret Manager at startup.

---

## All 91 Tools

### 🔍 Discovery & Hunting (12 tools)

| Tool | Description |
|------|-------------|
| `get_scc_findings` | Fetch active SCC vulnerabilities by severity |
| `top_vulnerability_findings` | Top SCC findings sorted by severity |
| `get_finding_remediation` | Remediation guidance for SCC findings |
| `query_cloud_logging` | Query Cloud Audit Logs |
| `search_secops_udm` | Chronicle UDM search (YARA-L or field queries) |
| `search_security_events` | Search security events by type and time range |
| `list_secops_detections` | All detections — custom rules + curated rules + cases |
| `get_security_alerts` | Recent security alerts |
| `check_ingestion_health` | Unparsed log detection / parser failures |
| `lookup_entity` | Entity context lookup in Chronicle |
| `get_last_logins` | Recent login events |
| `get_last_detections` | Recent detection alerts |

### 🧠 Threat Intelligence (6 tools)

| Tool | Description |
|------|-------------|
| `enrich_indicator` | Enrich IP/domain/hash/URL via GTI/VirusTotal |
| `get_ip_report` | Detailed IP report |
| `get_domain_report` | Detailed domain report |
| `get_file_report` | Detailed file hash report |
| `search_threat_actors` | Threat actor profiles (APT groups) |
| `search_malware_families` | Malware family profiles |

### 🛡️ Detection Engineering (8 tools)

| Tool | Description |
|------|-------------|
| `list_rules` | List all YARA-L rules |
| `create_rule` | Create a YARA-L 2.0 rule |
| `get_rule` | Get rule details by ID |
| `toggle_rule` | Enable/disable a rule |
| `list_rule_errors` | Rule compilation/execution errors |
| `create_detection_rule_for_scc_finding` | Auto-generate YARA-L from SCC finding |
| `extract_iocs_from_detections` | Bulk IOC extraction from detections |
| `vertex_ai_investigate` | Gemini-powered threat analysis |

### 📋 Data Tables (3 tools)

| Tool | Description |
|------|-------------|
| `list_data_tables` | List all Data Tables |
| `get_data_table` | Read table contents |
| `update_data_table` | Write/update rows |

### 📂 SOAR Cases (17 tools)

| Tool | Description |
|------|-------------|
| `list_cases` / `secops_list_cases` | List cases |
| `get_last_cases` | Recent cases summary |
| `secops_get_case` | **Full case report** — entities, MITRE, hashes, processes, detections |
| `secops_update_case` | Update priority, status, description |
| `get_case_alerts` / `secops_list_case_alerts` | Alerts for a case |
| `secops_get_case_alert` | Alert details |
| `secops_update_case_alert` | Update alert |
| `add_case_comment` / `secops_create_case_comment` | Add comments |
| `secops_list_case_comments` | List comments |
| `get_case_overview` | Stats and priority breakdown |
| `update_case_priority` | Change priority |
| `close_case` | Close with reason |
| `secops_execute_bulk_close_case` | Bulk close |
| `secops_execute_manual_action` | Execute SOAR action |

### 🎭 SOAR Playbooks (6 tools)

| Tool | Description |
|------|-------------|
| `list_playbooks` | List playbooks |
| `get_playbook` | Playbook details |
| `create_playbook` | Create playbook |
| `create_containment_playbook` | Auto-generate containment playbook |
| `export_playbook_template` | Export as template |
| `clone_playbook` | Clone existing playbook |

### 🔒 Containment (7 tools)

| Tool | Description |
|------|-------------|
| `purge_email_o365` | Delete email from O365 mailbox |
| `suspend_okta_user` | Suspend + clear Okta sessions |
| `revoke_azure_ad_sessions` | Revoke Azure AD / Entra ID sessions |
| `revoke_aws_access_keys` | Disable AWS IAM keys |
| `revoke_aws_sts_sessions` | Deny STS assumed-role sessions |
| `revoke_gcp_sa_keys` | Delete GCP service account keys |
| `isolate_crowdstrike_host` | Network-isolate via CrowdStrike |

### 📊 Logging & Monitoring (6 tools)

| Tool | Description |
|------|-------------|
| `list_log_names` | Available log names |
| `list_log_entries` | Log entries with filters |
| `list_log_buckets` | Logging buckets |
| `get_log_bucket` | Bucket details |
| `list_log_views` | Log views |
| `query_ingestion_stats` | **Daily ingestion bandwidth (GB)** from Cloud Monitoring |

### 🔧 SecOps Admin (7 tools)

| Tool | Description |
|------|-------------|
| `list_parsers` | Parsers / log types |
| `validate_parser` | Test parser against raw log |
| `list_feeds` | Ingestion feeds |
| `get_feed` | Feed details |
| `list_data_access_labels` | Data access labels |
| `list_data_access_scopes` | Data access scopes |
| `query_secops_audit_logs` | Platform audit logs |

### 📊 Analytics (5 tools)

| Tool | Description |
|------|-------------|
| `get_mttx_metrics` | MTTR / MTTC response metrics |
| `bigquery_list_dataset_ids` | BigQuery datasets |
| `bigquery_list_table_ids` | Tables in a dataset |
| `bigquery_get_dataset_info` / `bigquery_get_table_info` | Metadata |
| `bigquery_execute_sql` | Execute SQL |

### 🔑 IAM (3 tools)

| Tool | Description |
|------|-------------|
| `get_iam_policy` | Full project IAM policy |
| `get_service_accounts` | List SAs with key counts |
| `check_iam_permissions` | Check roles for a specific user/SA |

### 🧠 Session & Investigation (5 tools)

| Tool | Description |
|------|-------------|
| `create_session` | Create investigation session |
| `get_session` | Retrieve session state |
| `set_session_context` | Update session context |
| `add_investigation_note` | Timestamped investigation notes |
| `autonomous_investigate` | **Flagship:** End-to-end pipeline — enrich → hunt → assess → detect → respond → report |

---

## API Endpoints

| Endpoint | Transport | Client |
|----------|-----------|--------|
| `GET /` | HTTP | Web UI (built-in chat) |
| `GET /health` | HTTP | Health check (exempt from auth) |
| `GET /api/tools` | HTTP | Tool listing |
| `POST /api/chat` | HTTP | Multi-turn orchestration (Web UI) |
| `GET /sse` | SSE | Claude Desktop / MCP clients |
| `POST /messages/` | HTTP | SSE message handler |
| `POST /mcp` | Streamable HTTP | Gemini CLI |
| `GET /api/approvals` | HTTP | List approval requests (filter with `?state=pending`) |
| `GET /api/approvals/{id}` | HTTP | Fetch a specific approval |
| `POST /api/approvals/{id}/decide` | HTTP | Approve or deny (caller roles must intersect rule's approver_groups) |
| `GET /api/audit/verify` | HTTP | Verify the hash-chained audit log is intact |

---

## Author

**David Adohen** — Google SecOps / Google Threat Intelligence
