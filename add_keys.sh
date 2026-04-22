#!/bin/bash
# MCP Boss — add/update integration credentials.
#
# Two modes:
#   1. Interactive plaintext (legacy, dev-only):
#        ./add_keys.sh
#   2. Secret Manager references (recommended for prod):
#        ./add_keys.sh --use-secret-manager
#      This stores each credential in Google Secret Manager (creating secrets if
#      needed) and points the Cloud Run env vars at sm:// references.
#
# Required env vars: SECOPS_PROJECT_ID, SECOPS_CUSTOMER_ID
# Optional:          REGION (default us-central1), SERVICE (default mcp-boss)
set -euo pipefail

: "${SECOPS_PROJECT_ID:?Set SECOPS_PROJECT_ID (target GCP project)}"
: "${SECOPS_CUSTOMER_ID:?Set SECOPS_CUSTOMER_ID (Chronicle customer UUID)}"
SERVICE="${SERVICE:-mcp-boss}"
REGION="${REGION:-us-central1}"
SECOPS_REGION="${SECOPS_REGION:-us}"

USE_GSM=0
for arg in "$@"; do
  case "$arg" in
    --use-secret-manager|--gsm) USE_GSM=1 ;;
  esac
done

read_secret() {
  local label="$1"; local -n out="$2"; local hidden="${3:-1}"
  if [ "$hidden" -eq 1 ]; then
    read -rsp "$label: " out; echo ""
  else
    read -rp "$label: " out
  fi
}

echo "=========================================="
echo "  MCP Boss — credential configuration"
echo "  project=$SECOPS_PROJECT_ID  service=$SERVICE  region=$REGION"
echo "  mode: $([ $USE_GSM -eq 1 ] && echo 'Secret Manager' || echo 'plaintext env (dev)')"
echo "=========================================="
echo "Press Enter to skip any credential you don't have yet."
echo ""

declare -A VALS
read_secret "VirusTotal / GTI API Key"           VALS[GTI_API_KEY]
read_secret "O365 Tenant ID"                     VALS[O365_TENANT_ID] 0
read_secret "O365 Client ID"                     VALS[O365_CLIENT_ID] 0
read_secret "O365 Client Secret"                 VALS[O365_CLIENT_SECRET]
read_secret "Okta Domain (e.g. company.okta.com)" VALS[OKTA_DOMAIN] 0
read_secret "Okta API Token"                     VALS[OKTA_API_TOKEN]
read_secret "Azure AD Tenant ID"                 VALS[AZURE_AD_TENANT_ID] 0
read_secret "Azure AD Client ID"                 VALS[AZURE_AD_CLIENT_ID] 0
read_secret "Azure AD Client Secret"             VALS[AZURE_AD_CLIENT_SECRET]
read_secret "AWS Access Key ID"                  VALS[SOAR_AWS_KEY]
read_secret "AWS Secret Access Key"              VALS[SOAR_AWS_SECRET]
read_secret "CrowdStrike Client ID"              VALS[CROWDSTRIKE_CLIENT_ID] 0
read_secret "CrowdStrike Client Secret"          VALS[CROWDSTRIKE_CLIENT_SECRET]
read_secret "CrowdStrike Base URL [https://api.crowdstrike.com]" VALS[CROWDSTRIKE_BASE_URL] 0
VALS[CROWDSTRIKE_BASE_URL]="${VALS[CROWDSTRIKE_BASE_URL]:-https://api.crowdstrike.com}"
read_secret "Google Chat webhook URL (approvals)" VALS[GOOGLE_CHAT_WEBHOOK_URL] 0
read_secret "Generic approval webhook URL (optional)" VALS[APPROVAL_WEBHOOK_URL] 0
read_secret "Generic approval webhook HMAC secret (optional)" VALS[APPROVAL_WEBHOOK_SECRET]

# Keys that are genuinely sensitive (get routed through Secret Manager in GSM mode).
SENSITIVE_KEYS=(GTI_API_KEY O365_CLIENT_SECRET OKTA_API_TOKEN AZURE_AD_CLIENT_SECRET \
                SOAR_AWS_KEY SOAR_AWS_SECRET CROWDSTRIKE_CLIENT_SECRET \
                GOOGLE_CHAT_WEBHOOK_URL APPROVAL_WEBHOOK_SECRET)

ENV_VARS="SECOPS_PROJECT_ID=${SECOPS_PROJECT_ID},SECOPS_CUSTOMER_ID=${SECOPS_CUSTOMER_ID},SECOPS_REGION=${SECOPS_REGION}"
SET_SECRETS=""

secret_name_for() { echo "mcp-boss-$(echo "$1" | tr '[:upper:]_' '[:lower:]-')"; }

store_in_gsm() {
  local key="$1"; local value="$2"; local sname
  sname=$(secret_name_for "$key")
  gcloud secrets describe "$sname" --project "$SECOPS_PROJECT_ID" >/dev/null 2>&1 || \
    gcloud secrets create "$sname" --project "$SECOPS_PROJECT_ID" --replication-policy=automatic
  printf "%s" "$value" | gcloud secrets versions add "$sname" --project "$SECOPS_PROJECT_ID" --data-file=- >/dev/null
  echo "$sname"
}

for key in "${!VALS[@]}"; do
  v="${VALS[$key]}"
  [ -z "$v" ] && continue
  if [ $USE_GSM -eq 1 ] && [[ " ${SENSITIVE_KEYS[*]} " == *" $key "* ]]; then
    sname=$(store_in_gsm "$key" "$v")
    SET_SECRETS="${SET_SECRETS:+${SET_SECRETS},}${key}=${sname}:latest"
    echo "Stored $key in Secret Manager (secret: $sname)"
  else
    # Escape commas for gcloud CSV env format.
    esc_v=${v//,/\\,}
    ENV_VARS="${ENV_VARS},${key}=${esc_v}"
  fi
done

echo ""
echo "Updating Cloud Run service '$SERVICE' in '$REGION'..."
GCLOUD_ARGS=(--region "$REGION" --project "$SECOPS_PROJECT_ID" --quiet)
[ -n "$ENV_VARS" ]     && GCLOUD_ARGS+=(--update-env-vars "$ENV_VARS")
[ -n "$SET_SECRETS" ]  && GCLOUD_ARGS+=(--update-secrets "$SET_SECRETS")

gcloud run services update "$SERVICE" "${GCLOUD_ARGS[@]}"

echo ""
echo "Checking health..."
URL=$(gcloud run services describe "$SERVICE" --region "$REGION" --project "$SECOPS_PROJECT_ID" --format='value(status.url)')
curl -sS "${URL}/health" | python3 -m json.tool || echo "(health endpoint did not return JSON)"
