# Permissions Guide — What Access Does This Product Need?

## The Short Version

This product needs **read access** to your security data and **write access** to create detection rules and investigation cases. It doesn't need admin access to your infrastructure. It can't delete your data, modify your infrastructure, or access anything outside your security tools.

Think of it like giving a security analyst a desk in your SOC — they can see the dashboards, search the logs, write detection rules, and open cases. They can't reformat the servers.

---

## Required Permissions (Must Have)

These are needed for the core features to work. Without them, the product won't function.

### Google SecOps (Chronicle SIEM)

| Permission | IAM Role | What It Allows | Why It's Needed |
|---|---|---|---|
| Search UDM events | `roles/chronicle.viewer` | Read security events, search logs | The core search functionality — "search for failed logins" |
| List detection rules | `roles/chronicle.viewer` | See existing YARA-L rules | Shows what detections you have |
| List alerts | `roles/chronicle.viewer` | Read detection alerts | Shows what rules are firing |
| Create rules | `roles/chronicle.editor` | Write new YARA-L rules | Auto-creates detection rules during investigations |
| Manage Data Tables | `roles/chronicle.editor` | Read/write Data Tables | Updates blocklists, VIP lists during containment |
| Create cases | `roles/chronicle.editor` | Create SOAR cases | Opens investigation cases during autonomous investigations |
| Manage playbooks | `roles/chronicle.admin` | Create/list playbooks | Auto-creates containment playbooks |

**Minimum for read-only mode:** `roles/chronicle.viewer`
**Recommended for full autonomous mode:** `roles/chronicle.admin`

### Vertex AI (Gemini)

| Permission | IAM Role | What It Allows | Why It's Needed |
|---|---|---|---|
| Generate content | `roles/aiplatform.user` | Call Gemini models | Powers natural language search translation and investigation reports |

**This is required** for the chat interface, natural language search, and report generation.

### Security Command Center (SCC)

| Permission | IAM Role | What It Allows | Why It's Needed |
|---|---|---|---|
| Read findings | `roles/securitycenter.findingsViewer` | See vulnerabilities and misconfigurations | "Check SCC findings" and vulnerability-based investigations |

**Note:** SCC permissions are at the **organization level**, not the project level. If your SCC is configured at the org, grant this role at the org.

### Cloud Logging

| Permission | IAM Role | What It Allows | Why It's Needed |
|---|---|---|---|
| Read logs | `roles/logging.viewer` | Query Cloud Logging entries | Audit log searches, SOAR debugging, ingestion health monitoring |

---

## Optional Permissions (For Specific Integrations)

These are only needed if you use the specific containment tools. Skip any integration you don't use.

### VirusTotal / Google Threat Intelligence

| What's Needed | How to Get It |
|---|---|
| VirusTotal API key | Free at https://www.virustotal.com/gui/join-us |

**Not an IAM role** — this is a separate API key you enter during setup. Without it, the enrichment tools (IP/domain/hash lookup) won't work, but everything else will.

### Office 365 Email Purge (Microsoft Graph)

| What's Needed | How to Get It |
|---|---|
| Azure AD App Registration with `Mail.ReadWrite` permission | Create in Azure Portal → App Registrations |
| `O365_TENANT_ID` | Your Azure AD tenant ID |
| `O365_CLIENT_ID` | The app registration's client ID |
| `O365_CLIENT_SECRET` | The app registration's client secret |

**What this allows:** Hard Delete emails from any mailbox by Message-ID. Used for phishing containment.

**What this does NOT allow:** Read email content, send emails, or access mailboxes beyond deleting specific messages.

### Okta User Suspension

| What's Needed | How to Get It |
|---|---|
| Okta API token with `okta.users.manage` scope | Create in Okta Admin → Security → API → Tokens |
| `OKTA_DOMAIN` | Your Okta org domain (e.g., company.okta.com) |
| `OKTA_API_TOKEN` | The API token you created |

**What this allows:** Suspend a user account and clear their active sessions. Used for compromised account containment.

**What this does NOT allow:** Delete users, modify group membership, or access user credentials.

### Azure AD / Entra ID Session Revocation

| What's Needed | How to Get It |
|---|---|
| Azure AD App Registration with `User.RevokeSessions.All` permission | Create in Azure Portal → App Registrations |
| `AZURE_AD_TENANT_ID` | Your Azure AD tenant ID |
| `AZURE_AD_CLIENT_ID` | The app registration's client ID |
| `AZURE_AD_CLIENT_SECRET` | The app registration's client secret |

**What this allows:** Revoke all active sign-in sessions for a specific user. Used when a user's token is compromised.

**What this does NOT allow:** Read user data, reset passwords, or modify directory objects.

### AWS IAM Credential Revocation

| What's Needed | How to Get It |
|---|---|
| AWS IAM user with `iam:ListAccessKeys`, `iam:UpdateAccessKey`, `iam:PutUserPolicy` | Create in AWS IAM Console |
| `SOAR_AWS_KEY` | The access key ID |
| `SOAR_AWS_SECRET` | The secret access key |

**What this allows:** Disable active access keys and revoke STS sessions for compromised IAM users. Used when AWS credentials are leaked.

**What this does NOT allow:** Create users, modify infrastructure, access S3 data, or launch EC2 instances.

### GCP Service Account Key Revocation

| What's Needed | How to Get It |
|---|---|
| `roles/iam.serviceAccountKeyAdmin` on the target project | Grant via IAM Console |

**What this allows:** Delete user-managed service account keys when a GCP SA key is leaked.

**What this does NOT allow:** Create service accounts, modify IAM policies, or access cloud resources.

### CrowdStrike Endpoint Isolation

| What's Needed | How to Get It |
|---|---|
| CrowdStrike API client with `Hosts: Write` scope | Create in Falcon Console → API Clients |
| `CROWDSTRIKE_CLIENT_ID` | The API client ID |
| `CROWDSTRIKE_CLIENT_SECRET` | The API client secret |

**What this allows:** Network-isolate a host (the host can still talk to CrowdStrike cloud for remote forensics but is cut off from the internal network). Used for active compromise containment.

**What this does NOT allow:** Uninstall the Falcon sensor, access host files, or run commands on endpoints.

---

## How to Set It Up

### Step 1: Grant Google Cloud Permissions

Run these commands (replace `YOUR_PROJECT` with your project ID):

```bash
PROJECT_ID="YOUR_PROJECT"

# Create the service account
gcloud iam service-accounts create native-mcp-sa \
    --display-name="MCP Server Service Account"

SA_EMAIL="native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com"

# Required permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/chronicle.admin"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/aiplatform.user"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/securitycenter.findingsViewer"

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="roles/logging.viewer"
```

### Step 2: Add Optional Integration Keys

Run the interactive setup:

```bash
bash add_keys.sh
```

Enter each key when prompted. Press Enter to skip any integration you don't use.

---

## Principle of Least Privilege — What We DON'T Ask For

| Permission | Do We Need It? | Why Not? |
|---|---|---|
| `roles/owner` | ❌ No | We don't need full project control |
| `roles/editor` | ❌ No | We don't need to modify infrastructure |
| `roles/compute.admin` | ❌ No | We don't touch VMs or networks |
| `roles/storage.admin` | ❌ No | We don't access Cloud Storage buckets |
| `roles/bigquery.admin` | ❌ No | We don't query your data warehouse |
| `roles/iam.admin` | ❌ No | We don't modify IAM policies (except revoking leaked SA keys) |
| Access to your source code | ❌ No | We only access security telemetry |
| Access to your databases | ❌ No | We only access security logs |
| Access to your customer data | ❌ No | We only access security events in UDM format |

---

## Security Architecture

```
┌─────────────────────────────────────────────┐
│           YOUR Google Cloud Project          │
│                                              │
│  ┌──────────────┐     ┌──────────────────┐  │
│  │  MCP Server   │────▶│  SecOps (SIEM)   │  │
│  │  (Cloud Run)  │────▶│  SCC             │  │
│  │               │────▶│  Cloud Logging   │  │
│  │  Runs as:     │────▶│  Vertex AI       │  │
│  │  native-mcp-sa│     └──────────────────┘  │
│  └──────┬───────┘                            │
│         │                                     │
│         │ Optional (your keys, your accounts) │
│         │                                     │
│         ├──▶ VirusTotal (API key)            │
│         ├──▶ Office 365 (App Registration)   │
│         ├──▶ Okta (API token)                │
│         ├──▶ Azure AD (App Registration)     │
│         ├──▶ AWS IAM (Access key)            │
│         └──▶ CrowdStrike (API client)        │
│                                              │
│  Everything runs INSIDE your project.        │
│  Nothing leaves your environment.            │
│  Your permissions. Your data. Your control.  │
└─────────────────────────────────────────────┘
```

---

## Frequently Asked Questions

**Q: Can this product read my emails?**
A: No. The O365 integration can only delete specific emails by Message-ID (for phishing purge). It cannot read email content, search inboxes, or send emails.

**Q: Can this product access my cloud infrastructure (VMs, databases, storage)?**
A: No. It only accesses security tools: SecOps, SCC, Cloud Logging, and Vertex AI. It has zero access to compute, storage, databases, or networking.

**Q: What happens if the service account is compromised?**
A: The service account has read-only access to security data and write access only to detection rules and cases. An attacker could read your security logs and create (not delete) rules — but cannot access your infrastructure, customer data, or modify your cloud environment.

**Q: Can I run this in read-only mode?**
A: Yes. Grant only `roles/chronicle.viewer` instead of `roles/chronicle.admin`. The search, enrichment, and reporting tools will work. Auto-rule-creation, case creation, and playbook creation will be disabled.

**Q: Does this product phone home or send data externally?**
A: No. It runs entirely in your Google Cloud project. The only external calls are to VirusTotal (if you configure it) and to the third-party integrations you explicitly enable (Okta, O365, AWS, CrowdStrike). All of those calls go to YOUR accounts using YOUR API keys.

**Q: Is the source code auditable?**
A: Yes. It's fully open source: https://github.com/dadohen/Google-Native-MCP-Server
