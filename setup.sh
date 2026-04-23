#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# MCP Boss — Setup Script
# ═══════════════════════════════════════════════════════════════
#
# Usage:
#   # Interactive (clone first):
#   git clone https://github.com/dadohen/MCP-Boss.git
#   cd MCP-Boss && ./setup.sh
#
#   # One-liner with arguments:
#   curl -sL https://raw.githubusercontent.com/dadohen/MCP-Boss/main/setup.sh | bash -s -- \
#     --project your-project-id \
#     --customer your-secops-customer-id \
#     --gti-key your-vt-api-key
#
#   # Minimal (GTI key optional):
#   curl -sL https://raw.githubusercontent.com/dadohen/MCP-Boss/main/setup.sh | bash -s -- \
#     --project my-project --customer abc123def456
#
# ═══════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Parse arguments ──
PROJECT_ID=""
CUSTOMER_ID=""
REGION="us"
GTI_KEY=""
SERVICE_NAME="mcp-boss"

while [[ $# -gt 0 ]]; do
    case $1 in
        --project)     PROJECT_ID="$2"; shift 2 ;;
        --customer)    CUSTOMER_ID="$2"; shift 2 ;;
        --region)      REGION="$2"; shift 2 ;;
        --gti-key)     GTI_KEY="$2"; shift 2 ;;
        --service)     SERVICE_NAME="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: ./setup.sh --project PROJECT_ID --customer SECOPS_CUSTOMER_ID [--region us] [--gti-key KEY] [--service mcp-boss]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║          🛡️  MCP Boss — Setup                   ║"
echo "║     Autonomous Security Operations Server       ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Fill in missing values interactively (only works if not piped) ──
if [ -z "$PROJECT_ID" ]; then
    DEFAULT_PROJECT=$(gcloud config get-value project 2>/dev/null || true)
    if [ -t 0 ]; then
        read -p "GCP Project ID [$DEFAULT_PROJECT]: " PROJECT_ID
        PROJECT_ID=${PROJECT_ID:-$DEFAULT_PROJECT}
    else
        PROJECT_ID=$DEFAULT_PROJECT
    fi
fi

if [ -z "$PROJECT_ID" ]; then
    echo -e "${RED}Error: Project ID is required. Use --project YOUR_PROJECT_ID${NC}"
    exit 1
fi

if [ -z "$CUSTOMER_ID" ]; then
    if [ -t 0 ]; then
        read -p "SecOps Customer ID: " CUSTOMER_ID
    fi
fi

if [ -z "$CUSTOMER_ID" ]; then
    echo -e "${RED}Error: SecOps Customer ID is required. Use --customer YOUR_CUSTOMER_ID${NC}"
    exit 1
fi

if [ -z "$GTI_KEY" ] && [ -t 0 ]; then
    read -p "GTI/VirusTotal API Key (optional, Enter to skip): " GTI_KEY
fi

echo ""
echo -e "${CYAN}Configuration:${NC}"
echo "  Project:     $PROJECT_ID"
echo "  Customer ID: $CUSTOMER_ID"
echo "  Region:      $REGION"
echo "  GTI Key:     ${GTI_KEY:+configured}${GTI_KEY:-not set}"
echo "  Service:     $SERVICE_NAME"
echo ""

if [ -t 0 ]; then
    read -p "Continue? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

# ── Clone repo if not already in it ──
if [ ! -f "main.py" ] && [ ! -f "Dockerfile" ]; then
    echo -e "${YELLOW}Cloning MCP Boss...${NC}"
    TMPDIR=$(mktemp -d)
    git clone --depth 1 https://github.com/dadohen/MCP-Boss.git "$TMPDIR/MCP-Boss" 2>/dev/null
    cd "$TMPDIR/MCP-Boss"
    echo -e "${GREEN}✅ Cloned${NC}"
fi

# ── Step 1: Enable APIs ──
echo ""
echo -e "${YELLOW}Step 1: Enabling required APIs...${NC}"
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

# ── Step 2: Create service account + IAM roles ──
echo ""
echo -e "${YELLOW}Step 2: Setting up service account & IAM roles...${NC}"
SA_NAME="mcp-boss"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud iam service-accounts create $SA_NAME \
    --display-name="MCP Boss Service Account" \
    --project=$PROJECT_ID 2>/dev/null || true

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
echo -e "${GREEN}✅ Service account: $SA_EMAIL${NC}"

# ── Step 3: Build container ──
echo ""
echo -e "${YELLOW}Step 3: Building container...${NC}"
gcloud builds submit \
    --project=$PROJECT_ID \
    --tag gcr.io/$PROJECT_ID/mcp-boss:latest \
    --suppress-logs
echo -e "${GREEN}✅ Container built${NC}"

# ── Step 4: Deploy to Cloud Run ──
echo ""
echo -e "${YELLOW}Step 4: Deploying to Cloud Run...${NC}"

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

SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
    --project=$PROJECT_ID \
    --region=us-central1 \
    --format="value(status.url)")

# ── Step 5: Verify ──
echo ""
echo -e "${YELLOW}Step 5: Verifying...${NC}"
sleep 5
HEALTH=$(curl -s "$SERVICE_URL/health" 2>/dev/null)
TOOLS=$(echo $HEALTH | python3 -c "import sys,json; print(json.load(sys.stdin).get('tools',0))" 2>/dev/null || echo "?")

echo ""
echo -e "${GREEN}"
echo "══════════════════════════════════════════════════"
echo "  🛡️  MCP Boss — Deployed!  ($TOOLS tools)"
echo "══════════════════════════════════════════════════"
echo ""
echo "  Web UI:     $SERVICE_URL"
echo "  Health:     $SERVICE_URL/health"
echo "  MCP:        $SERVICE_URL/mcp"
echo "  SSE:        $SERVICE_URL/sse"
echo ""
echo "  Gemini CLI: gemini --tool-endpoint $SERVICE_URL/mcp"
echo -e "${NC}"
