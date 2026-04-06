# 🔒 Google-Native Autonomous MCP Server — Full Security Operations Suite

A production-ready Model Context Protocol (MCP) server with **60 tools** spanning the complete security operations lifecycle — from discovery and hunting through intelligence enrichment, automated containment, case management, and autonomous investigation.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   MCP Client (LLM)                      │
│          Vertex AI / Claude / GPT / Custom              │
└──────────────────────┬──────────────────────────────────┘
                       │ SSE (Server-Sent Events)
                       ▼
┌─────────────────────────────────────────────────────────┐
│           Google-Native MCP Server v2.0                 │
│           (Cloud Run — 60 Tools — Serverless)           │
│                                                         │
│  🔍 DISCOVERY        🧠 INTELLIGENCE    📋 MANAGEMENT  │
│  ├─ SCC Findings     ├─ GTI/VT Enrich   ├─ Data Tables │
│  ├─ Cloud Logging    ├─ IOC Extraction   ├─ YARA-L Rules│
│  ├─ UDM Search       └─ Vertex AI        └─ SOAR Cases │
│  ├─ Detections                                          │
│  └─ Ingestion Health                                    │
│                                                         │
│  📧 EMAIL            🔑 IDENTITY        ☁️ CLOUD       │
│  └─ O365 Purge       ├─ Okta Suspend    ├─ AWS Key Kill│
│                      └─ Azure AD Revoke ├─ AWS STS Kill│
│  🖥️ ENDPOINT                            └─ GCP SA Kill │
│  └─ CrowdStrike                                        │
│     Isolate                                             │
│                                                         │
│  Auth: Workload Identity + ADC (zero embedded secrets)  │
└─────────────────────────────────────────────────────────┘
```

## 60 Tools — Complete Reference (Updated April 6, 2026)

**All tools now include:**
- ✅ Real API integrations (not stubs)
- ✅ Native Gemini tool calling
- ✅ Time range support (hours_back, start_time, end_time)
- ✅ Comprehensive error handling
- ✅ JSON + natural language responses

**See [`docs/WHAT_THIS_DOES.md`](docs/WHAT_THIS_DOES.md) for the complete 60-tool breakdown by category.**

Key tools include:
- **Discovery**: SCC findings, Cloud Logging, SecOps UDM, YARA-L detections
- **Enrichment**: GTI/VirusTotal, IOC extraction, Vertex AI threat analysis  
- **Management**: Data Tables, Detection rules, SOAR cases
- **Containment**: O365 purge, Okta suspend, Azure AD revoke, AWS key revocation, GCP SA key deletion, CrowdStrike isolation
- **Autonomous**: End-to-end investigation pipeline with report generation

## Quick Start

**Option 1: Deploy to Cloud Run (Recommended)**
```bash
cd /home/linito/Desktop/Google_Native_MCP_Server
bash deploy_and_push.sh
```

**Option 2: Local Development**
```bash
chmod +x test_local.sh && ./test_local.sh
```

**See [`docs/DEPLOYMENT_GUIDE.md`](docs/DEPLOYMENT_GUIDE.md) for detailed setup.**

## Integrations

All integrations are optional. The server degrades gracefully — unconfigured tools return helpful error messages instead of crashing.

| Integration | Environment Variables | Required For |
|---|---|---|
| **Google SecOps** | `SECOPS_PROJECT_ID`, `SECOPS_CUSTOMER_ID`, `SECOPS_REGION` | All SecOps tools |
| **GTI / VirusTotal** | `GTI_API_KEY` | `enrich_indicator` |
| **Microsoft Graph** | `O365_TENANT_ID`, `O365_CLIENT_ID`, `O365_CLIENT_SECRET` | `purge_email_o365` |
| **Okta** | `OKTA_DOMAIN`, `OKTA_API_TOKEN` | `suspend_okta_user` |
| **Azure AD** | `AZURE_AD_TENANT_ID`, `AZURE_AD_CLIENT_ID`, `AZURE_AD_CLIENT_SECRET` | `revoke_azure_ad_sessions` |
| **AWS** | `SOAR_AWS_KEY`, `SOAR_AWS_SECRET` | `revoke_aws_access_keys`, `revoke_aws_sts_sessions` |
| **CrowdStrike** | `CROWDSTRIKE_CLIENT_ID`, `CROWDSTRIKE_CLIENT_SECRET` | `isolate_crowdstrike_host` |

## Documentation

See [`docs/DEPLOYMENT_GUIDE.md`](docs/DEPLOYMENT_GUIDE.md) for detailed deployment, security hardening, and troubleshooting.

## Files

```
├── main.py                          # MCP server (60 tools, 3.5KB)
├── requirements.txt                 # Python dependencies
├── Dockerfile                       # Production container (non-root)
├── deploy_and_push.sh               # One-command deploy + push to Cloud Run
├── add_keys.sh                      # Add API keys post-deployment
├── test_local.sh                    # Local development runner
├── .env.example                     # Environment variable template
├── .gitignore                       # Git ignore rules
├── README.md                        # This file
├── static/
│   └── index.html                   # Web UI (chat interface)
└── docs/
    ├── DEPLOYMENT_GUIDE.md          # Cloud Run setup + security hardening
    ├── DOCKER_INSTALL_GUIDE.md      # Local Docker quickstart
    ├── INSTALL_FROM_ZERO.md         # Complete GCP setup (zero → deployment)
    ├── PERMISSIONS_GUIDE.md         # IAM roles + least privilege
    └── WHAT_THIS_DOES.md            # Customer-facing product overview (all 60 tools)
```

## Security

- **Zero embedded secrets** — Workload Identity + ADC (no credential files)
- **Non-root container** — dedicated `mcpuser`
- **Authenticated endpoints** — IAP + service account validation
- **Input validation** — all parameters validated before API calls
- **Graceful degradation** — unconfigured integrations return errors, not crashes
- **Structured logging** — JSON format for Cloud Logging ingestion
- **Cost optimized** — Haiku LLM + prompt caching (~$0.10/day)
- **Time range support** — all query tools support hours_back, start_time, end_time

## Production Ready

✅ 60 real API integrations  
✅ Native Gemini tool calling  
✅ Workload Identity authentication  
✅ Cloud Run deployment  
✅ Autonomous investigation pipeline  
✅ Multi-channel reporting (email, Slack, Teams, GChat)  
✅ Cost optimized (Haiku + prompt caching)
✅ Comprehensive documentation

## Live Instance

**URL**: https://google-native-mcp-672020644906.us-central1.run.app  
**Chat Interface**: Web UI at `/` (requires authentication)  
**Tools API**: `POST /api/chat` (JSON request/response)  
**Tool List**: `GET /api/tools` (discovery)  
**Health**: `GET /health` (status)

## Author

David Adohen — Google SecOps, Google Threat Intel, Google Security  
**Last Updated**: April 6, 2026
