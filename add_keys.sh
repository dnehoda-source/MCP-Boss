#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Add API Keys to Your MCP Server
# Run: bash add_keys.sh
# ═══════════════════════════════════════════════════════════════

SERVICE="google-native-mcp"
REGION="us-central1"
PROJECT="tito-436719"
CUSTOMER="1d49deb2eaa7427ca1d1e78ccaa91c10"

echo "═══════════════════════════════════════════════════"
echo "  MCP Server — API Key Configuration"
echo "═══════════════════════════════════════════════════"
echo ""
echo "Press Enter to skip any key you don't have yet."
echo ""

# Collect keys
read -p "VirusTotal / GTI API Key: " GTI_KEY
read -p "O365 Tenant ID: " O365_TENANT
read -p "O365 Client ID: " O365_CLIENT
read -sp "O365 Client Secret: " O365_SECRET
echo ""
read -p "Okta Domain (e.g., company.okta.com): " OKTA_DOM
read -sp "Okta API Token: " OKTA_TOK
echo ""
read -p "Azure AD Tenant ID: " AZ_TENANT
read -p "Azure AD Client ID: " AZ_CLIENT
read -sp "Azure AD Client Secret: " AZ_SECRET
echo ""
read -sp "AWS Access Key ID: " AWS_KEY
echo ""
read -sp "AWS Secret Access Key: " AWS_SECRET
echo ""
read -p "CrowdStrike Client ID: " CS_CLIENT
read -sp "CrowdStrike Client Secret: " CS_SECRET
echo ""
read -p "CrowdStrike Base URL [https://api.crowdstrike.com]: " CS_URL
CS_URL=${CS_URL:-https://api.crowdstrike.com}

# Build env vars string
ENV_VARS="SECOPS_PROJECT_ID=${PROJECT}"
ENV_VARS="${ENV_VARS},SECOPS_CUSTOMER_ID=${CUSTOMER}"
ENV_VARS="${ENV_VARS},SECOPS_REGION=us"

[ -n "$GTI_KEY" ] && ENV_VARS="${ENV_VARS},GTI_API_KEY=${GTI_KEY}"
[ -n "$O365_TENANT" ] && ENV_VARS="${ENV_VARS},O365_TENANT_ID=${O365_TENANT}"
[ -n "$O365_CLIENT" ] && ENV_VARS="${ENV_VARS},O365_CLIENT_ID=${O365_CLIENT}"
[ -n "$O365_SECRET" ] && ENV_VARS="${ENV_VARS},O365_CLIENT_SECRET=${O365_SECRET}"
[ -n "$OKTA_DOM" ] && ENV_VARS="${ENV_VARS},OKTA_DOMAIN=${OKTA_DOM}"
[ -n "$OKTA_TOK" ] && ENV_VARS="${ENV_VARS},OKTA_API_TOKEN=${OKTA_TOK}"
[ -n "$AZ_TENANT" ] && ENV_VARS="${ENV_VARS},AZURE_AD_TENANT_ID=${AZ_TENANT}"
[ -n "$AZ_CLIENT" ] && ENV_VARS="${ENV_VARS},AZURE_AD_CLIENT_ID=${AZ_CLIENT}"
[ -n "$AZ_SECRET" ] && ENV_VARS="${ENV_VARS},AZURE_AD_CLIENT_SECRET=${AZ_SECRET}"
[ -n "$AWS_KEY" ] && ENV_VARS="${ENV_VARS},SOAR_AWS_KEY=${AWS_KEY}"
[ -n "$AWS_SECRET" ] && ENV_VARS="${ENV_VARS},SOAR_AWS_SECRET=${AWS_SECRET}"
[ -n "$CS_CLIENT" ] && ENV_VARS="${ENV_VARS},CROWDSTRIKE_CLIENT_ID=${CS_CLIENT}"
[ -n "$CS_SECRET" ] && ENV_VARS="${ENV_VARS},CROWDSTRIKE_CLIENT_SECRET=${CS_SECRET}"
[ -n "$CS_URL" ] && ENV_VARS="${ENV_VARS},CROWDSTRIKE_BASE_URL=${CS_URL}"

echo ""
echo "Updating Cloud Run service..."

gcloud run services update ${SERVICE} \
    --region ${REGION} \
    --update-env-vars="${ENV_VARS}" \
    --quiet

echo ""
echo "✅ Keys updated. Checking health..."
echo ""
curl -s https://${SERVICE}-672020644906.${REGION}.run.app/health | python3 -m json.tool
