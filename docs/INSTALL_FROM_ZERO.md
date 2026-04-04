# 🚀 From GitHub to Cloud Run — The "Explain It Like I'm 5" Install Guide

## What You're Building

You're taking code from GitHub, putting it in a box (Docker container), and running that box on Google's cloud (Cloud Run). When it's done, you'll have a URL that any AI can talk to — and that AI will be able to search your SIEM, check your threat intel, isolate endpoints, and purge phishing emails.

**Total time:** 15–20 minutes if everything goes smoothly.

---

## What You Need Before Starting

Check each box. If any are missing, follow the "How to get it" link.

- [ ] **A Google Cloud account with billing enabled**
  - How to get it: https://console.cloud.google.com → Sign up → Add a credit card
  - You won't be charged much (< $5/month for this server)

- [ ] **A Google Cloud project**
  - How to get it: https://console.cloud.google.com → Click the project dropdown at the top → "New Project" → Name it anything (e.g., `secops-mcp`) → Create

- [ ] **Google SecOps (Chronicle) instance**
  - You should already have this if you're reading this guide
  - You'll need your **Customer ID** (a UUID) — find it in SecOps Console → Settings → SIEM Settings

- [ ] **A computer with a terminal** (Mac Terminal, Linux terminal, or Windows PowerShell)

That's it. Everything else gets installed in the steps below.

---

## Step 1: Install the Google Cloud CLI

This is the tool that lets you talk to Google Cloud from your terminal.

### Mac
```bash
brew install google-cloud-sdk
```
Don't have brew? Install it first: https://brew.sh

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates gnupg curl
curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list
sudo apt-get update
sudo apt-get install -y google-cloud-cli
```

### Windows
Download the installer: https://cloud.google.com/sdk/docs/install#windows

### Verify It Works
```bash
gcloud version
```
You should see a version number. If you see "command not found," the install failed — try again.

---

## Step 2: Log In to Google Cloud

```bash
gcloud auth login
```

**What happens:** Your browser opens. Sign in with your Google account. Click "Allow."

Then set your project:
```bash
gcloud config set project YOUR_PROJECT_ID
```

Replace `YOUR_PROJECT_ID` with the project you created (e.g., `secops-mcp`). 

**Not sure what your project ID is?** Run:
```bash
gcloud projects list
```

---

## Step 3: Download the Code from GitHub

You have two options. Pick whichever is easier for you.

### Option A: Download as a ZIP (Easiest — No Git Required)

1. Open your browser and go to: **https://github.com/dnehoda-source/Google-Native-MCP-Server**
2. Look for the big green button that says **"<> Code"** — click it
3. In the dropdown menu, click **"Download ZIP"**
4. Your browser downloads a file called `Google-Native-MCP-Server-main.zip`
5. Find it in your Downloads folder and **unzip it** (double-click on Mac/Windows, or `unzip` on Linux)
6. Open your terminal and navigate to the unzipped folder:

```bash
cd ~/Downloads/Google-Native-MCP-Server-main
```

That's it. You have the code.

### Option B: Use Git (If You Have It Installed)

```bash
cd ~/Desktop
git clone https://github.com/dnehoda-source/Google-Native-MCP-Server.git
cd Google-Native-MCP-Server
```

**Don't have git and want to install it?**
- Mac: `xcode-select --install`
- Linux: `sudo apt install git`
- Windows: https://git-scm.com/download/win

**Not sure if you have git?** Type `git --version` in your terminal. If you see a version number, you have it. If you see "command not found," use Option A.

---

## Step 4: Enable the Required Google APIs

Google Cloud has hundreds of services. They're all turned off by default. We need to turn on the 7 that our server uses.

Here's what each one does:

| API | What It Does | Why We Need It |
|---|---|---|
| `run.googleapis.com` | **Cloud Run** — runs your server in the cloud | This is where your MCP server lives |
| `cloudbuild.googleapis.com` | **Cloud Build** — builds your Docker container | Packages your code into a container without needing Docker on your machine |
| `secretmanager.googleapis.com` | **Secret Manager** — stores API keys securely | Holds your VirusTotal/GTI API key so it's not in plain text |
| `securitycenter.googleapis.com` | **Security Command Center** — vulnerability scanner | The `get_scc_findings` tool queries this |
| `logging.googleapis.com` | **Cloud Logging** — audit logs | The `query_cloud_logging` tool queries this |
| `aiplatform.googleapis.com` | **Vertex AI** — Google's AI platform | The `vertex_ai_investigate` tool uses Gemini through this |
| `chronicle.googleapis.com` | **Google SecOps (Chronicle)** — your SIEM | The UDM search, detections, Data Tables, and rules tools all use this |

Copy and paste this one command to turn them all on:

```bash
gcloud services enable \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    secretmanager.googleapis.com \
    securitycenter.googleapis.com \
    logging.googleapis.com \
    aiplatform.googleapis.com \
    chronicle.googleapis.com
```

**What happens:** Google turns on all 7 services. Takes about 30 seconds. You'll see "Operation finished successfully" for each one.

**If you see "PERMISSION_DENIED":** You need to be a Project Owner or Editor. Ask whoever created the project to give you access.

---

## Step 5: Create a Service Account

The server needs an identity to talk to Google's APIs. That identity is called a "service account."

```bash
gcloud iam service-accounts create native-mcp-sa \
    --display-name="MCP Server Service Account"
```

Now give it permission to read your security data:

```bash
PROJECT_ID=$(gcloud config get-value project)

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/chronicle.viewer" --quiet

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/securitycenter.findingsViewer" --quiet

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/logging.viewer" --quiet

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/aiplatform.user" --quiet
```

**What happens:** You created a service account and gave it read-only access to your security tools. It can look but not touch.

**If you see "already exists":** That's fine — it was created before. Move on.

---

## Step 6: Add Your VirusTotal API Key (Optional)

This lets the server look up IPs, domains, and file hashes in VirusTotal. Skip this step if you don't have a VT key.

**Get a free key:** https://www.virustotal.com/gui/join-us → Sign up → Profile → API Key

```bash
echo -n "YOUR_VT_API_KEY_HERE" | gcloud secrets create gti-api-key \
    --data-file=- \
    --replication-policy="automatic"
```

Replace `YOUR_VT_API_KEY_HERE` with your actual key.

Now let the service account read it:

```bash
PROJECT_ID=$(gcloud config get-value project)

gcloud secrets add-iam-policy-binding gti-api-key \
    --member="serviceAccount:native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor" --quiet
```

**If you see "already exists":** The secret was created before. To update it:
```bash
echo -n "YOUR_NEW_KEY" | gcloud secrets versions add gti-api-key --data-file=-
```

---

## Step 7: Build the Container

This is where Google takes your code and packages it into a Docker container — in the cloud. You don't need Docker installed on your computer for this step.

```bash
PROJECT_ID=$(gcloud config get-value project)

gcloud builds submit --tag gcr.io/${PROJECT_ID}/google-native-mcp:latest
```

**What happens:** 
1. Google uploads your code (~50KB)
2. Google builds the Docker container in their cloud
3. Google stores the container in your project's Container Registry

**This takes 2–5 minutes.** You'll see lots of output. Wait for:
```
DONE
```

**If you see "PERMISSION_DENIED" or "Cloud Build API has not been enabled":**
Go back to Step 4 and make sure you enabled `cloudbuild.googleapis.com`.

---

## Step 8: Deploy to Cloud Run

This is the big one. This takes the container you just built and runs it on Google's servers.

```bash
PROJECT_ID=$(gcloud config get-value project)
SECOPS_CUSTOMER_ID="YOUR_CUSTOMER_ID_HERE"

gcloud run deploy google-native-mcp \
    --image gcr.io/${PROJECT_ID}/google-native-mcp:latest \
    --region us-central1 \
    --service-account native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com \
    --no-allow-unauthenticated \
    --memory 512Mi \
    --cpu 1 \
    --min-instances 0 \
    --max-instances 10 \
    --timeout 120 \
    --set-env-vars="SECOPS_PROJECT_ID=${PROJECT_ID},SECOPS_CUSTOMER_ID=${SECOPS_CUSTOMER_ID},SECOPS_REGION=us" \
    --quiet
```

⚠️ **Replace `YOUR_CUSTOMER_ID_HERE`** with your actual SecOps Customer ID (the UUID from SecOps Settings → SIEM Settings).

**What happens:**
1. Google creates a new Cloud Run service
2. It starts your container
3. It gives you a URL

You'll see something like:
```
Service [google-native-mcp] revision [google-native-mcp-00001-abc] has been deployed
Service URL: https://google-native-mcp-abc123-uc.a.run.app
```

**Copy that URL.** That's your MCP server.

---

## Step 9: Add the VirusTotal Secret (If You Did Step 6)

```bash
gcloud run services update google-native-mcp \
    --region us-central1 \
    --set-secrets="GTI_API_KEY=gti-api-key:latest"
```

---

## Step 10: Test It

```bash
SERVICE_URL=$(gcloud run services describe google-native-mcp \
    --region us-central1 \
    --format="value(status.url)")

curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
    ${SERVICE_URL}/health
```

**What you should see:**

```json
{
    "status": "healthy",
    "server": "google-native-mcp",
    "version": "2.0.0",
    "tools": 22,
    "project": "your-project-id",
    "region": "us",
    "integrations": {
        "gti": true,
        "o365": false,
        "okta": false,
        "azure_ad": false,
        "aws": false,
        "crowdstrike": false
    }
}
```

**If you see `"status": "healthy"` — YOU'RE DONE. 🎉**

The `false` values for O365, Okta, etc. are normal — those integrations are optional. The server works without them; those specific tools just won't be available until you add the credentials.

---

## Step 11: Connect an MCP Client

Your server is running. Now you need something to talk to it.

### Option A: Claude Code (Easiest)

```bash
SERVICE_URL=$(gcloud run services describe google-native-mcp \
    --region us-central1 \
    --format="value(status.url)")

claude mcp add google-security --transport sse ${SERVICE_URL}/sse
```

Now when you use Claude Code, it has access to all 22 security tools.

### Option B: Any MCP Client

Use these endpoints:
- **SSE Connection:** `https://YOUR_SERVICE_URL/sse`
- **Health Check:** `https://YOUR_SERVICE_URL/health`

All requests need an `Authorization: Bearer TOKEN` header. Get a token with:
```bash
gcloud auth print-identity-token
```

---

## 🎉 You're Done!

**What you have now:**
- A server running on Google Cloud (Cloud Run)
- 22 security tools accessible via MCP
- Automatic scaling (0 instances when idle = $0, scales up when used)
- Zero embedded secrets (Workload Identity handles everything)
- A health check endpoint to verify it's working

**Monthly cost:** $0 when idle. ~$5–$20/month with moderate usage. Cloud Run only charges when the server is actively handling requests.

---

## Troubleshooting — When Things Go Wrong

### "PERMISSION_DENIED" on any step

You need more permissions on the GCP project. Ask the project owner to grant you the **Editor** role:

```bash
gcloud projects add-iam-policy-binding YOUR_PROJECT \
    --member="user:YOUR_EMAIL" \
    --role="roles/editor"
```

### "Cloud Build" fails during Step 7

**Most common cause:** A typo in requirements.txt or main.py. Run this to see the build log:
```bash
gcloud builds list --limit=1
gcloud builds log $(gcloud builds list --limit=1 --format="value(id)")
```

The error message will tell you exactly what went wrong.

### Health check returns "degraded" or ADC error

The service account doesn't have the right permissions. Re-run Step 5 (the IAM binding commands).

### curl returns "403 Forbidden"

Your identity token expired. Get a fresh one:
```bash
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" ${SERVICE_URL}/health
```

### curl returns "Connection refused"

The service might be sleeping (min-instances = 0). The first request takes 2–3 seconds to wake it up. Try again.

### I want to update the code

```bash
cd ~/Desktop/Google-Native-MCP-Server
git pull  # get latest code
gcloud builds submit --tag gcr.io/${PROJECT_ID}/google-native-mcp:latest
gcloud run deploy google-native-mcp \
    --image gcr.io/${PROJECT_ID}/google-native-mcp:latest \
    --region us-central1
```

That's it — zero-downtime update.

### I want to delete everything

```bash
gcloud run services delete google-native-mcp --region us-central1
gcloud iam service-accounts delete native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com
gcloud secrets delete gti-api-key
```

---

## The Whole Thing in 30 Seconds

```bash
# 1. Login
gcloud auth login
gcloud config set project YOUR_PROJECT

# 2. Get the code
git clone https://github.com/dnehoda-source/Google-Native-MCP-Server.git
cd Google-Native-MCP-Server

# 3. Enable APIs
gcloud services enable run.googleapis.com cloudbuild.googleapis.com secretmanager.googleapis.com securitycenter.googleapis.com logging.googleapis.com aiplatform.googleapis.com chronicle.googleapis.com

# 4. Create service account + permissions
gcloud iam service-accounts create native-mcp-sa --display-name="MCP Server"
PROJECT_ID=$(gcloud config get-value project)
for ROLE in roles/chronicle.viewer roles/securitycenter.findingsViewer roles/logging.viewer roles/aiplatform.user; do
    gcloud projects add-iam-policy-binding $PROJECT_ID --member="serviceAccount:native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com" --role="$ROLE" --quiet
done

# 5. Build + Deploy
gcloud builds submit --tag gcr.io/${PROJECT_ID}/google-native-mcp:latest
gcloud run deploy google-native-mcp --image gcr.io/${PROJECT_ID}/google-native-mcp:latest --region us-central1 --service-account native-mcp-sa@${PROJECT_ID}.iam.gserviceaccount.com --no-allow-unauthenticated --memory 512Mi --set-env-vars="SECOPS_PROJECT_ID=${PROJECT_ID},SECOPS_CUSTOMER_ID=YOUR_CUSTOMER_ID,SECOPS_REGION=us" --quiet

# 6. Test
SERVICE_URL=$(gcloud run services describe google-native-mcp --region us-central1 --format="value(status.url)")
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" ${SERVICE_URL}/health
```

Done. Your autonomous SOC server is live. 🔥
