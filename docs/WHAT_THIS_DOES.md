# What Does This Product Do?

## The One Sentence Version

You type a question about your security. The system investigates it automatically — searches your logs, checks threat intelligence, creates detection rules, opens investigation cases, and writes you a full report. In 60 seconds instead of 45 minutes.

## The Problem It Solves

Today, when something suspicious happens in your Google Cloud environment, your security team does this:

1. An analyst sees an alert in the queue (could be 30 minutes to 3 hours before they get to it)
2. They copy the suspicious IP address
3. Open a new tab, go to VirusTotal, paste it, wait for results
4. Open another tab, go to Google SecOps, write a search query, run it
5. Read through the results, try to figure out what happened
6. If it's bad, they manually write a detection rule so it gets caught next time
7. They manually open an investigation case to track it
8. They write up their findings in a document or email
9. They decide what to contain — block the IP? Suspend the user? Isolate the laptop?

**That takes 45 minutes to 2 hours per incident.** Multiply by 50 incidents a day.

## What This Product Does Instead

You type:

```
investigate 198.51.100.42
```

And the system does ALL of that automatically:

```
Step 1: IDENTIFY (3 seconds)
  "What is this IP?"
  → Checks VirusTotal: 15/94 engines say it's malicious
  → Country: Russia, ASN: BULLETPROOF-HOSTING-LLC
  → Tags: malware, botnet, c2

Step 2: SEARCH (5 seconds)
  "Has this IP touched our environment?"
  → Searches 72 hours of your security logs
  → Found: 47 events — 3 internal hosts communicated with this IP
  → Traffic: HTTPS on port 443, consistent 60-second beacon interval

Step 3: ASSESS (1 second)
  "How bad is this?"
  → Severity: CRITICAL
  → Reason: Known malicious IP + active communication from internal hosts
  → Pattern matches C2 beacon behavior

Step 4: DETECT (3 seconds)
  "Will we catch this next time?"
  → Created a YARA-L detection rule automatically
  → Rule fires whenever any host contacts this IP
  → Also created a containment playbook that triggers when the rule fires

Step 5: RESPOND (2 seconds)
  "Who's tracking this?"
  → Created an investigation case in your SOAR platform
  → Assigned priority: CRITICAL
  → All evidence attached to the case

Step 6: CONTAIN (2 seconds)
  "Stop the bleeding."
  → Added IP to your blocklist (immediate)
  → CrowdStrike host isolation queued (waiting for analyst approval)
  → Okta user suspension available (waiting for analyst approval)

Step 7: REPORT (5 seconds)
  → Generated a full investigation report with:
     - Executive summary
     - Indicator details
     - SIEM findings
     - Threat assessment
     - Actions taken
     - Recommendations
     - MITRE ATT&CK mapping
```

**Total time: ~20 seconds.** Zero copy-paste. Zero tab switching. Zero manual work.

## What a Customer Sees

### Step 1: Deploy (15 minutes, one time)

You click a button. A setup wizard asks for:
- Your Google Cloud project ID
- Your SecOps Customer ID (found in SecOps Settings)
- Optionally: your VirusTotal API key (free)

The system deploys itself to your Google Cloud account. It runs on Cloud Run (serverless — costs $0 when idle, ~$5/month with normal use).

### Step 2: Authenticate (10 seconds)

Open the web interface. Sign in with your Google account. That's it. The system uses your existing Google Cloud permissions — no new passwords, no API keys to manage.

### Step 3: Use It

You see a simple chat interface. Type in plain English:

| What You Type | What Happens |
|---|---|
| "investigate 198.51.100.42" | Full autonomous investigation (search → enrich → detect → respond → contain → report) |
| "check SCC findings" | Shows your active cloud vulnerabilities sorted by severity |
| "search for failed logins in the last 24 hours" | Searches your SIEM using natural language (AI translates to the query language) |
| "show me all detection rules" | Lists your YARA-L rules with status |
| "what feeds are configured?" | Shows your data ingestion sources |
| "show ingestion stats" | Shows how much data each source is sending |
| "create a phishing containment playbook" | Builds a complete response playbook |
| "enrich domain evil-site.com" | Checks VirusTotal for domain reputation |
| "list open cases" | Shows your active investigation cases |

You don't need to know query languages. You don't need to know API endpoints. You don't need to switch between 5 different tools. Just ask.

## What Tools Are Inside

The system has 60 tools organized into categories:

### 🔍 Find Things
- Search your security logs (SIEM) in plain English
- Check Google Cloud for vulnerabilities (SCC)
- Look up any IP, domain, or file hash in threat intelligence
- Monitor your log ingestion health
- View detection alerts

### 🛡️ Detect Things
- List and manage your detection rules
- Auto-create new detection rules when threats are found
- Check for rule errors
- View what's triggering

### 📋 Manage Things
- Create and manage investigation cases
- Add comments and update case priority
- List and create response playbooks
- Manage your Data Tables (blocklists, VIP lists, etc.)

### ⚡ Stop Things
- Purge phishing emails from all inboxes (Office 365)
- Suspend compromised user accounts (Okta)
- Revoke compromised sessions (Azure AD)
- Disable leaked cloud credentials (AWS + GCP)
- Network-isolate infected endpoints (CrowdStrike)

### 📊 Understand Things
- View RBAC configurations
- Check parser status and validate new parsers
- Query Cloud Logging for audit trails
- AI-generated investigation reports (Gemini)

## How It's Different From What You Have Today

| Capability | Without This Product | With This Product |
|---|---|---|
| **Investigate an IP** | 45 min (5 tools, manual copy-paste) | 20 seconds (one command) |
| **Create a detection rule** | Write YARA-L manually, test, deploy | Auto-generated when threats are found |
| **Respond to phishing** | 30+ min per email (manual triage) | 60 seconds (auto-purge + session kill) |
| **Check cloud posture** | Log into SCC console, navigate, filter | "check SCC findings" |
| **Search your SIEM** | Write UDM queries manually | "search for failed logins from Russia" |
| **Track investigations** | Manual case creation in SOAR | Cases auto-created with full context |
| **Generate reports** | Write them manually in docs/email | AI-generated from real investigation data |

## Security

- **Your data stays in your cloud.** The system runs in YOUR Google Cloud project. Nothing leaves your environment.
- **Zero embedded secrets.** Authentication uses Google's Workload Identity — no passwords or API keys stored in the code.
- **Your permissions apply.** The system can only access what your Google Cloud account can access. It doesn't get special privileges.
- **Destructive actions require approval.** The system won't isolate a host or suspend a user without explicit approval. Blocklist updates are automatic; everything else asks first.
- **Open source.** You can read every line of code: https://github.com/dnehoda-source/Google-Native-MCP-Server

## Cost

| Component | Cost |
|---|---|
| Cloud Run (the server) | $0 when idle, ~$5/month with moderate use |
| Gemini (AI reports) | Included in Vertex AI pricing (minimal) |
| VirusTotal (threat intel) | Free tier: 4 lookups/minute, plenty for most SOCs |
| Everything else | Uses your existing Google SecOps, SCC, Cloud Logging — no additional licensing |

## Next Steps

Ready to try it? Follow the [Install Guide](INSTALL_FROM_ZERO.md) — takes about 15 minutes from zero to running.
