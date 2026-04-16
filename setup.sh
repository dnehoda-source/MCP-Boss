#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# MCP Boss — One-Click Setup Script
# ═══════════════════════════════════════════════════════════════
#
# Usage:
#   chmod +x setup.sh && ./setup.sh
#
# Or from Cloud Shell:
#   git clone https://github.com/dnehoda-source/MCP-Boss.git
#   cd MCP-Boss && chmod +x setup.sh && ./setup.sh
#
# Prerequisites:
#   - gcloud CLI authenticated (gcloud auth login)
#   - GCP project with billing enabled
#   - Chronicle/SecOps instance with customer ID
# ═══════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║          🛡️  MCP Boss — Setup Wizard            ║"
echo "║     Autonomous Security Operations Server       ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Step 1: Get configuration ──
echo -e "${YELLOW}Step 1: Configuration${NC}"
echo ""

# Project ID
DEFAULT_PROJECT=$(gcloud config get-value project 2>/dev/null)
read -p "GCP Project ID [$DEFAULT_PROJECT]: " PROJECT_ID
PROJECT_ID=${PROJECT_ID:-$DEFAULT_PROJECT}
if [ -z "$PROJECT_ID" ]; then
    echo -e "${RED}Error: Project ID is required.${NC}"
    exit 1
fi

# SecOps Customer ID
read -p "SecOps Customer ID (from Chronicle settings): " CUSTOMER_ID
if [ -z "$CUSTOMER_ID" ]; then
    echo -e "${RED}Error: SecOps Customer ID is required.${NC}"
    exit 1
fi

# Region
read -p "SecOps Region [us]: " REGION
REGION=${REGION:-us}

# GTI API Key
read -p "GTI/VirusTotal API Key (optional, press Enter to skip): " GTI_KEY

# Service name
read -p "Cloud Run service name [mcp-boss]: " SERVICE_NAME
SERVICE_NAME=${SERVICE_NAME:-mcp-boss}

echo ""
echo -e "${CYAN}Configuration:${NC}"
echo "  Project:     $PROJECT_ID"
echo "  Customer ID: $CUSTOMER_ID"
echo "  Region:      $REGION"
echo "  GTI Key:     ${GTI_KEY:+configured}${GTI_KEY:-not set}"
echo "  Service:     $SERVICE_NAME"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# ── Step 2: Enable APIs ──
echo ""
echo -e "${YELLOW}Step 2: Enabling required APIs...${NC}"
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
    --project=$PROJECT_ID --quiet
echo -e "${GREEN}✅ APIs enabled${NC}"

# ── Step 3: Create service account + IAM roles ──
echo ""
echo -e "${YELLOW}Step 3: Setting up service account & IAM roles...${NC}"
SA_NAME="mcp-boss"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# Create SA (ignore if exists)
gcloud iam service-accounts create $SA_NAME \
    --display-name="MCP Boss Service Account" \
    --project=$PROJECT_ID 2>/dev/null || true

# Grant required roles
ROLES=(
    "roles/chronicle.admin"
    "roles/securitycenter.findingsViewer"
    "roles/aiplatform.user"
    "roles/logging.viewer"
    "roles/bigquery.dataViewer"
    "roles/bigquery.jobUser"
    "roles/monitoring.viewer"
    "roles/iam.securityReviewer"
)

for ROLE in "${ROLES[@]}"; do
    echo "  Granting $ROLE..."
    gcloud projects add-iam-policy-binding $PROJECT_ID \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="$ROLE" \
        --condition=None \
        --quiet 2>/dev/null || true
done
echo -e "${GREEN}✅ Service account configured: $SA_EMAIL${NC}"

# ── Step 4: Build container ──
echo ""
echo -e "${YELLOW}Step 4: Building container image...${NC}"
gcloud builds submit \
    --project=$PROJECT_ID \
    --tag gcr.io/$PROJECT_ID/mcp-boss:latest \
    --suppress-logs
echo -e "${GREEN}✅ Container built${NC}"

# ── Step 5: Deploy to Cloud Run ──
echo ""
echo -e "${YELLOW}Step 5: Deploying to Cloud Run...${NC}"

ENV_VARS="SECOPS_PROJECT_ID=$PROJECT_ID,SECOPS_CUSTOMER_ID=$CUSTOMER_ID,SECOPS_REGION=$REGION"
if [ -n "$GTI_KEY" ]; then
    ENV_VARS="${ENV_VARS},GTI_API_KEY=$GTI_KEY"
fi

gcloud run deploy $SERVICE_NAME \
    --image gcr.io/$PROJECT_ID/mcp-boss:latest \
    --project=$PROJECT_ID \
    --region=us-central1 \
    --platform=managed \
    --service-account=$SA_EMAIL \
    --allow-unauthenticated \
    --set-env-vars="$ENV_VARS" \
    --memory=512Mi \
    --timeout=300 \
    --quiet

# Get the service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
    --project=$PROJECT_ID \
    --region=us-central1 \
    --format="value(status.url)")

# ── Step 6: Verify ──
echo ""
echo -e "${YELLOW}Step 6: Verifying deployment...${NC}"
sleep 5
HEALTH=$(curl -s "$SERVICE_URL/health" 2>/dev/null)
TOOLS=$(echo $HEALTH | python3 -c "import sys,json; print(json.load(sys.stdin).get('tools',0))" 2>/dev/null || echo "?")
STATUS=$(echo $HEALTH | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','unknown'))" 2>/dev/null || echo "unknown")

echo ""
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║          🛡️  MCP Boss — Deployed!               ║"
echo "╠══════════════════════════════════════════════════╣"
echo -e "║  Status:  ${GREEN}$STATUS${CYAN}                              ║"
echo -e "║  Tools:   ${GREEN}$TOOLS${CYAN}                                    ║"
echo "╠══════════════════════════════════════════════════╣"
echo -e "║  ${NC}Web UI:   ${GREEN}$SERVICE_URL${CYAN}  ║"
echo -e "║  ${NC}Health:   ${GREEN}$SERVICE_URL/health${CYAN}  ║"
echo -e "║  ${NC}MCP:      ${GREEN}$SERVICE_URL/mcp${CYAN}  ║"
echo -e "║  ${NC}SSE:      ${GREEN}$SERVICE_URL/sse${CYAN}  ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo "Connect Gemini CLI:"
echo "  gemini --tool-endpoint $SERVICE_URL/mcp"
echo ""
echo "Connect Claude Desktop (claude_desktop_config.json):"
echo "  {\"mcpServers\":{\"mcp-boss\":{\"url\":\"$SERVICE_URL/sse\"}}}"
echo ""
