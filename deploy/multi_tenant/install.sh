#!/usr/bin/env bash
# MCP Boss — multi-tenant installer.
#
# Runs terraform apply, builds/pushes the container image, rolls the Cloud Run
# service onto the new digest, and prints the service + approvals URLs.
#
# Usage:
#   ./install.sh --project <GCP_PROJECT_ID> --customer-id <CHRONICLE_UUID> \
#                [--region us-central1] [--secops-region us] \
#                [--service mcp-boss] [--repo mcp-boss]
#
# Prerequisites: gcloud (authenticated), terraform >= 1.5, docker (optional —
# we prefer `gcloud builds submit` so no local Docker is needed).

set -euo pipefail

PROJECT=""
REGION="us-central1"
CUSTOMER_ID=""
SECOPS_REGION="us"
SERVICE="mcp-boss"
REPO="mcp-boss"
SKIP_BUILD=0

while [[ $# -gt 0 ]]; do
  case $1 in
    --project)        PROJECT="$2";        shift 2 ;;
    --region)         REGION="$2";         shift 2 ;;
    --customer-id)    CUSTOMER_ID="$2";    shift 2 ;;
    --secops-region)  SECOPS_REGION="$2";  shift 2 ;;
    --service)        SERVICE="$2";        shift 2 ;;
    --repo)           REPO="$2";           shift 2 ;;
    --skip-build)     SKIP_BUILD=1;        shift ;;
    -h|--help)
      sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$PROJECT" || -z "$CUSTOMER_ID" ]]; then
  echo "Missing --project or --customer-id" >&2
  exit 1
fi

command -v gcloud    >/dev/null || { echo "gcloud not found in PATH" >&2; exit 1; }
command -v terraform >/dev/null || { echo "terraform not found in PATH" >&2; exit 1; }

TF_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$TF_DIR/../.." && pwd)"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${REPO}/${SERVICE}:latest"

echo "=========================================="
echo "  MCP Boss installer"
echo "  project  : $PROJECT"
echo "  region   : $REGION  (SecOps region: $SECOPS_REGION)"
echo "  customer : $CUSTOMER_ID"
echo "  service  : $SERVICE"
echo "  repo     : $REPO"
echo "=========================================="

echo ""
echo "[1/4] terraform init + apply"
cd "$TF_DIR"
terraform init -input=false
terraform apply -input=false -auto-approve \
  -var "project_id=${PROJECT}" \
  -var "region=${REGION}" \
  -var "secops_customer_id=${CUSTOMER_ID}" \
  -var "secops_region=${SECOPS_REGION}" \
  -var "service_name=${SERVICE}" \
  -var "image_repo=${REPO}"

if [[ $SKIP_BUILD -eq 0 ]]; then
  echo ""
  echo "[2/4] building and pushing image: $IMAGE"
  gcloud builds submit "$REPO_ROOT" --tag "$IMAGE" --project "$PROJECT" --quiet
else
  echo ""
  echo "[2/4] --skip-build set, leaving existing image in place"
fi

echo ""
echo "[3/4] rolling Cloud Run revision onto latest image"
gcloud run services update "$SERVICE" \
  --image "$IMAGE" \
  --region "$REGION" \
  --project "$PROJECT" \
  --quiet

echo ""
echo "[4/4] reading outputs"
SERVICE_URL=$(terraform output -raw service_url)
APPROVALS_URL=$(terraform output -raw approvals_url)

echo ""
echo "=========================================="
echo "  Installed"
echo "  Service URL : $SERVICE_URL"
echo "  Approvals   : $APPROVALS_URL"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Upload integration credentials (Secret Manager-backed):"
echo "       SECOPS_PROJECT_ID=$PROJECT SECOPS_CUSTOMER_ID=$CUSTOMER_ID \\"
echo "         $REPO_ROOT/add_keys.sh --use-secret-manager"
echo "  2. Point your Google Chat webhook / approver at: $APPROVALS_URL"
echo "  3. Health check:"
echo "       curl -sS $SERVICE_URL/health | python3 -m json.tool"
