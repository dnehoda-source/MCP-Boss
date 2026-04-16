# 🛡️ MCP Boss — Autonomous Security Operations Server

**89 tools** spanning the complete security operations lifecycle — discovery, hunting, threat intelligence, detection engineering, case management, SOAR automation, containment, and autonomous investigation — deployed as a single serverless endpoint on Google Cloud Run.

**Live Demo:** `https://mcp-boss-672020644906.us-central1.run.app`

## One-Click Deploy

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://shell.cloud.google.com/cloudshell/editor?cloudshell_git_repo=https://github.com/dnehoda-source/MCP-Boss&cloudshell_tutorial=setup.sh&cloudshell_open_in_editor=README.md)

Or manually:
```bash
git clone https://github.com/dnehoda-source/MCP-Boss.git
cd MCP-Boss
chmod +x setup.sh && ./setup.sh
```

The setup wizard will:
1. Enable all required GCP APIs
2. Create a service account with the right IAM roles
3. Build the container
4. Deploy to Cloud Run
5. Verify and print your endpoints

---

## How It Works

MCP Boss is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that gives any AI model (Gemini, Claude, GPT) full access to your security stack through natural language.

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
│              86 Tools · Python · FastMCP                      │
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
│  ├─ Azure AD     └─ STS Revoke  └─ Audit Logs               │
│  └─ CrowdStrike                                             │
└──────────────────────────────────────────────────────────────┘
                       │
          ┌────────────┴────────────┐
          │  Google Cloud APIs       │
          │  Chronicle · SCC · GTI   │
          │  Vertex AI · BigQuery    │
          │  Cloud Logging · IAM     │
          └─────────────────────────┘
```

**Key design:** Zero embedded secrets. All authentication uses Workload Identity Federation (ADC) — the Cloud Run service account authenticates to every Google API automatically. Third-party containment APIs (Okta, AWS, etc.) use environment variables backed by Secret Manager.

---

## Setup Guide

### Prerequisites

- Google Cloud project with billing enabled
- `gcloud` CLI installed and authenticated
- APIs enabled: Chronicle, SCC, Vertex AI, Cloud Logging, BigQuery
- SecOps (Chronicle) instance with customer ID

### Step 1: Clone the Repository

```bash
git clone https://github.com/dnehoda-source/MCP-Boss.git
cd MCP-Boss
```

### Step 2: Set Your Configuration

Edit environment variables in `Dockerfile` or set them in Cloud Run:

```bash
# Required
SECOPS_PROJECT_ID=your-gcp-project-id
SECOPS_CUSTOMER_ID=your-chronicle-customer-id
SECOPS_REGION=us                              # us, eu, or asia

# Required for threat intelligence
GTI_API_KEY=your-virustotal-api-key

# Optional — third-party containment (add as needed)
O365_TENANT_ID=...
O365_CLIENT_ID=...
O365_CLIENT_SECRET=...
OKTA_DOMAIN=your-org.okta.com
OKTA_API_TOKEN=...
AZURE_AD_TENANT_ID=...
AZURE_AD_CLIENT_ID=...
AZURE_AD_CLIENT_SECRET=...
SOAR_AWS_KEY=...
SOAR_AWS_SECRET=...
CROWDSTRIKE_CLIENT_ID=...
CROWDSTRIKE_CLIENT_SECRET=...
```

### Step 3: IAM Roles — Service Account Setup

Create a dedicated service account and grant the required roles:

```bash
PROJECT_ID=your-project-id
SA_NAME=mcp-boss
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# Create the service account
gcloud iam service-accounts create $SA_NAME \
  --display-name="MCP Boss Service Account" \
  --project=$PROJECT_ID

# ── REQUIRED ROLES ──

# Chronicle / SecOps — full SIEM access (search, rules, cases, detections)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/chronicle.admin"

# Security Command Center — read findings and vulnerabilities
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/securitycenter.findingsViewer"

# Vertex AI — Gemini-powered threat analysis
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/aiplatform.user"

# Cloud Logging — query audit logs
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/logging.viewer"

# BigQuery — security data lake queries
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/bigquery.dataViewer"
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/bigquery.jobUser"

# Cloud Run Invoker — allow public access to the service
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/run.invoker"

# ── OPTIONAL ROLES (for containment actions) ──

# IAM — revoke service account keys (GCP containment)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/iam.serviceAccountKeyAdmin"

# Storage — Cloud Build access (for deployment)
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/storage.admin"
```

**IAM Roles Summary:**

| Role | Purpose | Required? |
|------|---------|-----------|
| `roles/chronicle.admin` | SecOps: UDM search, rules, cases, detections, data tables, feeds, parsers | ✅ Yes |
| `roles/securitycenter.findingsViewer` | SCC: vulnerability findings, misconfigurations | ✅ Yes |
| `roles/aiplatform.user` | Vertex AI: Gemini threat analysis | ✅ Yes |
| `roles/logging.viewer` | Cloud Logging: audit log queries | ✅ Yes |
| `roles/bigquery.dataViewer` | BigQuery: security data lake | ✅ Yes |
| `roles/bigquery.jobUser` | BigQuery: execute SQL queries | ✅ Yes |
| `roles/run.invoker` | Cloud Run: service invocation | ✅ Yes |
| `roles/iam.serviceAccountKeyAdmin` | GCP containment: revoke SA keys | ⚙️ Optional |
| `roles/storage.admin` | Cloud Build deployment | ⚙️ Deploy only |

### Step 4: Build and Deploy

```bash
PROJECT_ID=your-project-id
SA_EMAIL="mcp-boss@${PROJECT_ID}.iam.gserviceaccount.com"

# Build the container
gcloud builds submit \
  --project=$PROJECT_ID \
  --tag gcr.io/$PROJECT_ID/mcp-boss:latest

# Deploy to Cloud Run
gcloud run deploy mcp-boss \
  --image gcr.io/$PROJECT_ID/mcp-boss:latest \
  --project=$PROJECT_ID \
  --region=us-central1 \
  --platform=managed \
  --service-account=$SA_EMAIL \
  --allow-unauthenticated \
  --set-env-vars="SECOPS_PROJECT_ID=$PROJECT_ID,SECOPS_CUSTOMER_ID=YOUR_CUSTOMER_ID,SECOPS_REGION=us,GTI_API_KEY=YOUR_GTI_KEY"
```

### Step 5: Verify

```bash
# Health check
curl https://mcp-boss-XXXXXXXXXX.us-central1.run.app/health

# Expected:
# {"status":"healthy","server":"google-native-mcp","version":"3.2.2","tools":86,...}
```

### Step 6: Connect a Client

**Web UI (built-in):**
Open `https://mcp-boss-XXXXXXXXXX.us-central1.run.app` in a browser.

**Gemini CLI:**
```bash
gemini --tool-endpoint https://mcp-boss-XXXXXXXXXX.us-central1.run.app/mcp
```

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "mcp-boss": {
      "url": "https://mcp-boss-XXXXXXXXXX.us-central1.run.app/sse"
    }
  }
}
```

---

## All 86 Tools

### 🔍 Discovery & Hunting (12 tools)

| Tool | Description |
|------|-------------|
| `get_scc_findings` | Fetch active SCC vulnerabilities by severity |
| `top_vulnerability_findings` | Top SCC findings sorted by severity |
| `get_finding_remediation` | Remediation guidance for SCC finding categories |
| `query_cloud_logging` | Query Cloud Audit Logs with filters |
| `search_secops_udm` | Chronicle UDM search (YARA-L or field queries) |
| `search_security_events` | Search security events by type and time range |
| `list_secops_detections` | List all detections (custom + curated rules + cases) |
| `get_security_alerts` | Get recent security alerts |
| `check_ingestion_health` | Check for unparsed logs / parser failures |
| `lookup_entity` | Look up entity context in Chronicle |
| `get_last_logins` | Recent login events |
| `get_last_detections` | Recent detection alerts |

### 🧠 Threat Intelligence (6 tools)

| Tool | Description |
|------|-------------|
| `enrich_indicator` | Enrich IP/domain/hash/URL via GTI/VirusTotal |
| `get_ip_report` | Detailed VT report for an IP address |
| `get_domain_report` | Detailed VT report for a domain |
| `get_file_report` | Detailed VT report for a file hash |
| `search_threat_actors` | Search threat actor profiles (APT groups) |
| `search_malware_families` | Search malware family profiles |

### 🛡️ Detection Engineering (8 tools)

| Tool | Description |
|------|-------------|
| `list_rules` | List all YARA-L rules with status |
| `create_rule` | Create a new YARA-L 2.0 detection rule |
| `get_rule` | Get full rule details by ID |
| `toggle_rule` | Enable or disable a detection rule |
| `list_rule_errors` | List rule compilation/execution errors |
| `create_detection_rule_for_scc_finding` | Auto-generate YARA-L rule from SCC finding |
| `extract_iocs_from_detections` | Bulk extract IOCs from recent detections |
| `vertex_ai_investigate` | Gemini-powered threat analysis and assessment |

### 📋 Data Table Management (3 tools)

| Tool | Description |
|------|-------------|
| `list_data_tables` | List all SecOps Data Tables |
| `get_data_table` | Read a Data Table's contents |
| `update_data_table` | Write/update rows in a Data Table |

### 📂 SOAR Case Management — Legacy (7 tools)

| Tool | Description |
|------|-------------|
| `list_cases` | List SOAR cases |
| `get_last_cases` | Recent cases summary |
| `get_case_alerts` | Get alerts for a specific case |
| `get_case_overview` | Overview with stats and priorities |
| `add_case_comment` | Add a comment to a case |
| `update_case_priority` | Change case priority |
| `close_case` | Close a case with reason |

### 📂 SOAR Case Management — SecOps SDK (10 tools)

| Tool | Description |
|------|-------------|
| `secops_list_cases` | List cases via official SDK |
| `secops_get_case` | Get case details via SDK |
| `secops_update_case` | Update case fields via SDK |
| `secops_list_case_alerts` | List alerts for a case |
| `secops_get_case_alert` | Get alert details |
| `secops_update_case_alert` | Update alert status/fields |
| `secops_create_case_comment` | Add case comment via SDK |
| `secops_list_case_comments` | List case comments |
| `secops_execute_bulk_close_case` | Bulk close multiple cases |
| `secops_execute_manual_action` | Execute a manual SOAR action |

### 🎭 SOAR Playbooks (5 tools)

| Tool | Description |
|------|-------------|
| `list_playbooks` | List all SOAR playbooks |
| `get_playbook` | Get playbook details and steps |
| `create_playbook` | Create a new playbook |
| `create_containment_playbook` | Auto-generate containment playbook |
| `export_playbook_template` | Export playbook as reusable template |
| `clone_playbook` | Clone an existing playbook |

### 📧 Email Containment (1 tool)

| Tool | Description |
|------|-------------|
| `purge_email_o365` | Hard/soft delete email from O365 mailbox via Microsoft Graph |

### 🔑 Identity Containment (2 tools)

| Tool | Description |
|------|-------------|
| `suspend_okta_user` | Suspend Okta user + clear all sessions |
| `revoke_azure_ad_sessions` | Revoke all Azure AD / Entra ID sign-in sessions |

### ☁️ Cloud Credential Containment (3 tools)

| Tool | Description |
|------|-------------|
| `revoke_aws_access_keys` | Disable all active AWS IAM access keys |
| `revoke_aws_sts_sessions` | Deny pre-existing STS assumed-role sessions |
| `revoke_gcp_sa_keys` | Delete all user-managed GCP service account keys |

### 🖥️ Endpoint Containment (1 tool)

| Tool | Description |
|------|-------------|
| `isolate_crowdstrike_host` | Network-isolate host via CrowdStrike Falcon |

### 📊 Cloud Logging (5 tools)

| Tool | Description |
|------|-------------|
| `list_log_names` | List available log names |
| `list_log_entries` | List log entries with filters |
| `list_log_buckets` | List Cloud Logging buckets |
| `get_log_bucket` | Get bucket details |
| `list_log_views` | List log views in a bucket |

### 🔧 SecOps Administration (7 tools)

| Tool | Description |
|------|-------------|
| `list_parsers` | List all configured parsers/log types |
| `validate_parser` | Test a parser against a raw log sample |
| `list_feeds` | List data ingestion feeds |
| `get_feed` | Get feed details |
| `query_ingestion_stats` | Check ingestion volume and health |
| `list_data_access_labels` | List data access control labels |
| `list_data_access_scopes` | List data access control scopes |

### 📊 Analytics & Audit (4 tools)

| Tool | Description |
|------|-------------|
| `query_secops_audit_logs` | Query SecOps platform audit logs |
| `get_mttx_metrics` | Calculate MTTR/MTTC response metrics |
| `bigquery_list_dataset_ids` | List BigQuery datasets |
| `bigquery_list_table_ids` | List tables in a BigQuery dataset |
| `bigquery_get_dataset_info` | Get dataset metadata |
| `bigquery_get_table_info` | Get table schema and metadata |
| `bigquery_execute_sql` | Execute SQL query against BigQuery |

### 🧠 Session & Investigation (4 tools)

| Tool | Description |
|------|-------------|
| `create_session` | Create investigation session with context |
| `get_session` | Retrieve session state |
| `set_session_context` | Update session context (target user, IP, etc.) |
| `add_investigation_note` | Add timestamped note to investigation |

### 🚀 Autonomous Investigation (1 tool)

| Tool | Description |
|------|-------------|
| `autonomous_investigate` | **Flagship:** End-to-end pipeline — enrich → hunt → assess → detect → respond → report. Takes any trigger (IP, domain, hash, description) and executes the full SOC workflow automatically. |

---

## API Endpoints

| Endpoint | Transport | Purpose |
|----------|-----------|---------|
| `GET /` | HTTP | Web UI (chat interface) |
| `GET /health` | HTTP | Health check + tool count |
| `GET /api/tools` | HTTP | List all available tools |
| `POST /api/chat` | HTTP | Chat with multi-turn orchestration (Web UI) |
| `GET /sse` | SSE | MCP SSE transport (Claude Desktop) |
| `POST /messages/` | HTTP | MCP message handler (SSE sessions) |
| `POST /mcp` | Streamable HTTP | MCP Streamable HTTP (Gemini CLI) |

---

## Architecture Notes

- **Auth:** Workload Identity Federation (ADC) — zero static JSON keys
- **Runtime:** Python 3.11 + FastMCP + Starlette + Uvicorn on Cloud Run
- **SecOps SDK:** Uses official `google-secops-mcp` library (`SecOpsClient.chronicle`)
- **Multi-turn:** Web UI `/api/chat` supports up to 20 orchestration turns per request
- **Dual MCP:** Full 86-tool server on `/sse` + focused 24-tool subset on `/mcp` for Gemini CLI (Gemini API tool limit)

---

## Author

David Adohen — Google SecOps / Google Threat Intelligence
