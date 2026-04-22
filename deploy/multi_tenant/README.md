# Multi-tenant deploy (scaffold)

Goal: one command to install MCP Boss into any GCP project, with no hand-editing
of `main.py` and no fork.

Status: scaffold. The Terraform here sketches the right shape but is not yet
exhaustive (IAM bindings, Secret Manager, Artifact Registry, Cloud Run service
are stubbed). Fill in before shipping v1 of the installer.

## Target UX

```bash
# From inside a target GCP project's Cloud Shell:
curl -fsSL https://raw.githubusercontent.com/<owner>/MCP-Boss/main/deploy/multi_tenant/install.sh \
  | bash -s -- --project my-customer-project --region us-central1
```

The install script:

1. Enables the required APIs (securitycenter, logging, bigquery, aiplatform, run, artifactregistry, secretmanager).
2. Grants the Compute Engine default SA the IAM roles listed in `iam.tf`.
3. Creates Secret Manager entries (empty) for the integrations the customer opts into (GTI, Okta, Azure, AWS, CrowdStrike, O365, SOAR).
4. Builds the image from the public repo and pushes to the target's Artifact Registry.
5. Deploys to Cloud Run with `SECOPS_PROJECT_ID=$PROJECT` and `SECOPS_CUSTOMER_ID=$CUSTOMER_ID` passed in as env vars.
6. Prints the service URL and the `/api/approvals` URL to paste into Google Chat.

## What is already abstracted

- `variables.tf`: everything project-specific is a variable.
- `iam.tf`: role bindings applied to the resolved SA.
- `main.py` is fully parameterised. A grep for the previously-hardcoded IDs
  returns zero matches:

```bash
grep -n "tito-436719\|1d49deb2eaa7427ca1d1e78ccaa91c10" main.py
# (no output: both IDs have been removed)
```

The runtime reads everything from env. `SECOPS_PROJECT_ID` and
`SECOPS_CUSTOMER_ID` are the two you must set; the rest are optional and gate
specific integrations. Secrets can be plaintext env vars for local dev or
`sm://` Secret Manager references for Cloud Run (see `secrets_resolver.py`).

## Required environment variables

| var                  | required? | purpose                                                         |
|----------------------|-----------|-----------------------------------------------------------------|
| `SECOPS_PROJECT_ID`  | yes       | GCP project that owns the Chronicle / SecOps instance.          |
| `SECOPS_CUSTOMER_ID` | yes       | Chronicle customer (instance) UUID.                             |
| `SECOPS_REGION`      | no        | Chronicle region; defaults to `us`.                             |
| `PORT`               | no        | Cloud Run sets this automatically; defaults to 8080 locally.    |

## Auth / access control

| var                  | required?         | purpose                                                        |
|----------------------|-------------------|----------------------------------------------------------------|
| `OAUTH_CLIENT_ID`    | yes in prod       | Google OAuth client ID. When set, every request must carry a Google OIDC ID token whose `aud` matches. When unset, the server runs in local-dev mode with no auth. |
| `ALLOWED_EMAILS`     | optional          | Comma-separated allowlist applied after token verification.    |
| `ROLE_MAP_PATH`      | optional          | Path to a YAML file mapping emails / domains to approver roles (see `policy_and_approvals/policies.yaml` for the role names). |
| `ROLE_MAP_JSON`      | optional          | Inline JSON alternative to `ROLE_MAP_PATH`. Takes precedence.  |
| `AUTH_EXEMPT_PATHS`  | optional          | Comma-separated path prefixes that bypass auth (defaults: `/health`, `/static`). |

## Policy, approvals, audit

| var                        | required? | purpose                                                   |
|----------------------------|-----------|-----------------------------------------------------------|
| `MCP_BOSS_AUDIT_PATH`      | no        | File path for the hash-chained audit log. Default `/var/log/mcp-boss/audit.jsonl`. |
| `GOOGLE_CHAT_WEBHOOK_URL`  | no        | Incoming-webhook URL for the approvals Chat space. Enables Google Chat channel. |
| `APPROVAL_WEBHOOK_URL`     | no        | Generic approvals webhook (PagerDuty / Opsgenie / ServiceNow). |
| `APPROVAL_WEBHOOK_SECRET`  | no        | HMAC-SHA256 signing key for the generic webhook payload.  |
| `PUBLIC_BASE_URL`          | no        | Public base URL used to build Approve / Deny buttons in Chat cards. |

## Integration credentials (plaintext or `sm://<secret-name>` references)

| var                        | integration          |
|----------------------------|----------------------|
| `GTI_API_KEY`              | Google Threat Intel / VirusTotal. |
| `SOAR_BASE_URL`, `SOAR_API_KEY` | SOAR (Chronicle SOAR / Siemplify). |
| `O365_TENANT_ID`, `O365_CLIENT_ID`, `O365_CLIENT_SECRET` | Microsoft Graph (email purge). |
| `OKTA_DOMAIN`, `OKTA_API_TOKEN` | Okta (user suspend). |
| `AZURE_AD_TENANT_ID`, `AZURE_AD_CLIENT_ID`, `AZURE_AD_CLIENT_SECRET` | Entra ID (session revoke). |
| `SOAR_AWS_KEY`, `SOAR_AWS_SECRET` | AWS (IAM key / STS containment). |
| `CROWDSTRIKE_CLIENT_ID`, `CROWDSTRIKE_CLIENT_SECRET`, `CROWDSTRIKE_BASE_URL` | CrowdStrike Falcon (host isolation). |
| `GEMINI_MODEL`             | Vertex AI model name; defaults to `gemini-2.5-flash`. |

Any credential env var can accept a `sm://<project>/<secret>/<version>` reference
instead of a plaintext value; `secrets_resolver.py` fetches it via Secret
Manager on startup and caches it. Missing optional creds just disable the
corresponding tools; the server starts either way.
