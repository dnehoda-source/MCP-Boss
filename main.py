"""
Google-Native Autonomous MCP Server — Full Security Operations Suite
=====================================================================
The complete autonomous security operations toolkit bridging every Google Cloud
Security pillar plus third-party containment APIs into a single MCP endpoint.

TOOL CATEGORIES:
  🔍 DISCOVERY & HUNTING (read-only)
    - get_scc_findings          → Security Command Center vulnerabilities
    - query_cloud_logging       → Cloud Audit Logs
    - search_secops_udm         → Chronicle UDM / YARA-L search
    - list_secops_detections    → YARA-L detection alerts
    - check_ingestion_health    → Unparsed log monitoring

  🧠 INTELLIGENCE & ENRICHMENT
    - enrich_indicator          → GTI / VirusTotal (IP, domain, hash, URL)
    - extract_iocs_from_detections → Bulk IOC extraction from detection alerts
    - vertex_ai_investigate     → Gemini-powered threat analysis

  📋 DATA TABLE MANAGEMENT (SecOps)
    - list_data_tables          → List all Data Tables
    - get_data_table            → Read a Data Table's contents
    - update_data_table         → Overwrite/append rows to a Data Table

  🛡️ DETECTION MANAGEMENT (SecOps)
    - list_rules                → List YARA-L rules and their status
    - toggle_rule               → Enable or disable a YARA-L rule

  📧 EMAIL CONTAINMENT (Microsoft Graph)
    - purge_email_o365          → Hard Delete email from all inboxes by Message-ID

  🔑 IDENTITY CONTAINMENT
    - suspend_okta_user         → Suspend user + clear sessions in Okta
    - revoke_azure_ad_sessions  → Revoke all sign-in sessions in Azure AD / Entra ID

  ☁️ CLOUD CREDENTIAL CONTAINMENT
    - revoke_aws_access_keys    → Disable all active AWS IAM access keys
    - revoke_aws_sts_sessions   → Deny all pre-existing STS assumed-role sessions
    - revoke_gcp_sa_keys        → Delete all user-managed GCP service account keys

  🖥️ ENDPOINT CONTAINMENT
    - isolate_crowdstrike_host  → Network-isolate a host via CrowdStrike Falcon

  📂 SOAR CASE MANAGEMENT
    - create_soar_case          → Create a new SOAR case
    - update_soar_case          → Update priority, add comments, close a case

Deployed as a single Docker container on Cloud Run.
Auth: Workload Identity + ADC. Zero embedded secrets.

Author: David Adohen
"""

import os
import json
import logging
import re
import requests
import google.auth
from google.auth.transport.requests import Request as GCPRequest
from google.auth.exceptions import DefaultCredentialsError, RefreshError
from google.cloud import securitycenter
from google.cloud import logging as cloud_logging
from google.api_core.exceptions import (
    GoogleAPICallError,
    PermissionDenied,
    NotFound,
    ResourceExhausted,
)
from mcp.server.fastmcp import FastMCP
from datetime import datetime, timedelta, timezone

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

SECOPS_PROJECT_ID = os.getenv("SECOPS_PROJECT_ID", "YOUR_PROJECT_ID")
SECOPS_CUSTOMER_ID = os.getenv("SECOPS_CUSTOMER_ID", "YOUR_CUSTOMER_ID")
SECOPS_REGION = os.getenv("SECOPS_REGION", "us")
GTI_API_KEY = os.getenv("GTI_API_KEY", "")

# Third-party integration keys (stored in Secret Manager)
O365_CLIENT_ID = os.getenv("O365_CLIENT_ID", "")
O365_CLIENT_SECRET = os.getenv("O365_CLIENT_SECRET", "")
O365_TENANT_ID = os.getenv("O365_TENANT_ID", "")
OKTA_DOMAIN = os.getenv("OKTA_DOMAIN", "")
OKTA_API_TOKEN = os.getenv("OKTA_API_TOKEN", "")
AZURE_AD_TENANT_ID = os.getenv("AZURE_AD_TENANT_ID", "")
AZURE_AD_CLIENT_ID = os.getenv("AZURE_AD_CLIENT_ID", "")
AZURE_AD_CLIENT_SECRET = os.getenv("AZURE_AD_CLIENT_SECRET", "")
AWS_ACCESS_KEY_ID = os.getenv("SOAR_AWS_KEY", "")
AWS_SECRET_ACCESS_KEY = os.getenv("SOAR_AWS_SECRET", "")
CS_CLIENT_ID = os.getenv("CROWDSTRIKE_CLIENT_ID", "")
CS_CLIENT_SECRET = os.getenv("CROWDSTRIKE_CLIENT_SECRET", "")
CS_BASE_URL = os.getenv("CROWDSTRIKE_BASE_URL", "https://api.crowdstrike.com")

SECOPS_BASE_URL = (
    f"https://{SECOPS_REGION}-chronicle.googleapis.com/v1alpha"
    f"/projects/{SECOPS_PROJECT_ID}/locations/{SECOPS_REGION}"
    f"/instances/{SECOPS_CUSTOMER_ID}"
)

# ═══════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format='{"severity":"%(levelname)s","message":"%(message)s","tool":"%(name)s"}',
)
logger = logging.getLogger("google-native-mcp")

# ═══════════════════════════════════════════════════════════════
# MCP SERVER
# ═══════════════════════════════════════════════════════════════

app_mcp = FastMCP("google-native-mcp", json_response=True)

# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════


def validate_project_id(pid: str) -> str:
    if not pid or not re.match(r"^[a-z][a-z0-9\-]{4,28}[a-z0-9]$", pid):
        raise ValueError(f"Invalid project ID: '{pid}'")
    return pid


def validate_indicator(ind: str) -> str:
    if not ind or len(ind) > 256:
        raise ValueError("Indicator must be non-empty and under 256 chars.")
    if not re.match(r"^[a-zA-Z0-9\.\-\:\/\_\@]+$", ind):
        raise ValueError(f"Invalid indicator format: '{ind}'")
    return ind


def get_adc_token() -> str:
    try:
        creds, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        creds.refresh(GCPRequest())
        return creds.token
    except DefaultCredentialsError:
        raise RuntimeError("No ADC found. Configure Workload Identity or run gcloud auth application-default login.")
    except RefreshError as e:
        raise RuntimeError(f"ADC token refresh failed: {e}")


def _get_o365_token() -> str:
    """Get Microsoft Graph API access token via client credentials flow."""
    if not all([O365_TENANT_ID, O365_CLIENT_ID, O365_CLIENT_SECRET]):
        raise RuntimeError("O365 credentials not configured. Set O365_TENANT_ID, O365_CLIENT_ID, O365_CLIENT_SECRET.")
    resp = requests.post(
        f"https://login.microsoftonline.com/{O365_TENANT_ID}/oauth2/v2.0/token",
        data={
            "client_id": O365_CLIENT_ID,
            "client_secret": O365_CLIENT_SECRET,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        },
        timeout=15,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"O365 token error [{resp.status_code}]: {resp.text[:300]}")
    return resp.json()["access_token"]


def _get_crowdstrike_token() -> str:
    """Get CrowdStrike Falcon API OAuth2 token."""
    if not all([CS_CLIENT_ID, CS_CLIENT_SECRET]):
        raise RuntimeError("CrowdStrike credentials not configured. Set CROWDSTRIKE_CLIENT_ID and CROWDSTRIKE_CLIENT_SECRET.")
    resp = requests.post(
        f"{CS_BASE_URL}/oauth2/token",
        data={"client_id": CS_CLIENT_ID, "client_secret": CS_CLIENT_SECRET},
        timeout=15,
    )
    if resp.status_code != 201:
        raise RuntimeError(f"CrowdStrike token error [{resp.status_code}]: {resp.text[:300]}")
    return resp.json()["access_token"]


def _secops_headers() -> dict:
    return {
        "Authorization": f"Bearer {get_adc_token()}",
        "Content-Type": "application/json",
    }


# ═══════════════════════════════════════════════════════════════
# 🔍 DISCOVERY & HUNTING
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def get_scc_findings(project_id: str, severity: str = "CRITICAL", max_results: int = 10) -> str:
    """Fetch ACTIVE vulnerabilities from Security Command Center."""
    try:
        project_id = validate_project_id(project_id)
        max_results = min(max(1, max_results), 50)
        client = securitycenter.SecurityCenterClient()
        findings = client.list_findings(request={
            "parent": f"projects/{project_id}",
            "filter": f'state="ACTIVE" AND severity="{severity.upper()}"',
        })
        results = []
        for i, f in enumerate(findings):
            if i >= max_results:
                break
            results.append({
                "resource": f.finding.resource_name,
                "category": f.finding.category,
                "severity": str(f.finding.severity),
                "create_time": str(f.finding.create_time),
                "external_uri": f.finding.external_uri,
                "description": (f.finding.description or "")[:500],
            })
        logger.info(f"SCC: {len(results)} {severity} findings for {project_id}")
        return json.dumps({"scc_findings": results, "count": len(results)})
    except (PermissionDenied, NotFound, ValueError, GoogleAPICallError) as e:
        return json.dumps({"error": type(e).__name__, "detail": str(e)})


@app_mcp.tool()
def query_cloud_logging(project_id: str, filter_string: str, max_results: int = 10) -> str:
    """Query Google Cloud Logging for IAM changes, compute events, and audit trails."""
    try:
        project_id = validate_project_id(project_id)
        if not filter_string or len(filter_string.strip()) < 10:
            return json.dumps({"error": "Filter too broad", "detail": "Minimum 10 chars required."})
        client = cloud_logging.Client(project=project_id)
        entries = client.list_entries(filter_=filter_string, max_results=min(max_results, 50))
        logs = [{"timestamp": str(e.timestamp), "severity": e.severity, "payload": str(e.payload)[:2000]} for e in entries]
        logger.info(f"Cloud Logging: {len(logs)} entries for {project_id}")
        return json.dumps({"cloud_logs": logs, "count": len(logs)})
    except (PermissionDenied, ResourceExhausted, ValueError, GoogleAPICallError) as e:
        return json.dumps({"error": type(e).__name__, "detail": str(e)})


@app_mcp.tool()
def search_secops_udm(query: str, hours_back: int = 24) -> str:
    """Execute a UDM search or YARA-L query in Google SecOps (Chronicle)."""
    try:
        if not query or len(query.strip()) < 5:
            return json.dumps({"error": "Query too short"})
        hours_back = min(max(1, hours_back), 8760)
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = requests.post(
            f"{SECOPS_BASE_URL}/dashboardQueries:execute",
            headers=_secops_headers(),
            json={"dashboardQuery": {"yaraLQuery": query, "timeRange": {"startTime": start, "endTime": end}}},
            timeout=60,
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"SecOps API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def list_secops_detections(hours_back: int = 24, max_results: int = 50) -> str:
    """List recent YARA-L detection alerts with rule names, severity, and outcomes."""
    try:
        hours_back = min(max(1, hours_back), 8760)
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = requests.post(
            f"{SECOPS_BASE_URL}/rules:listDetections",
            headers=_secops_headers(),
            json={"page_size": min(max_results, 1000), "start_time": start, "end_time": end},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            detections = []
            for d in data.get("detections", [])[:max_results]:
                det = d.get("detection", {}).get("detection", {})
                detections.append({
                    "rule_name": det.get("ruleName", "unknown"),
                    "severity": det.get("severity", "unknown"),
                    "detection_time": d.get("detectionTime", ""),
                    "outcomes": det.get("outcomes", {}),
                })
            return json.dumps({"detections": detections, "count": len(detections)})
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def check_ingestion_health(log_type: str = "", hours_back: int = 1) -> str:
    """
    Check for unparsed logs in SecOps. If log_type is provided, checks that specific source.
    Returns unparsed volume to identify silent parser failures.
    """
    try:
        query = 'raw = /.*/ parsed = false'
        if log_type:
            query += f' log_type = "{log_type}"'
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        resp = requests.post(
            f"{SECOPS_BASE_URL}/dashboardQueries:execute",
            headers=_secops_headers(),
            json={"dashboardQuery": {"yaraLQuery": query, "timeRange": {"startTime": start, "endTime": end}}},
            timeout=30,
        )
        if resp.status_code == 200:
            return json.dumps({"status": "ok", "query": query, "result": resp.json()})
        return json.dumps({"error": f"API [{resp.status_code}]"})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🧠 INTELLIGENCE & ENRICHMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def enrich_indicator(indicator: str, indicator_type: str = "auto") -> str:
    """Enrich an IP, domain, URL, or file hash using Google Threat Intel / VirusTotal."""
    try:
        indicator = validate_indicator(indicator)
        if not GTI_API_KEY:
            return json.dumps({"error": "GTI_API_KEY not configured"})

        if indicator_type == "auto":
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator):
                indicator_type = "ip"
            elif re.match(r"^[a-fA-F0-9]{32}$", indicator) or re.match(r"^[a-fA-F0-9]{64}$", indicator):
                indicator_type = "hash"
            elif "/" in indicator or "http" in indicator.lower():
                indicator_type = "url"
            else:
                indicator_type = "domain"

        vt = "https://www.virustotal.com/api/v3"
        urls = {"ip": f"{vt}/ip_addresses/{indicator}", "domain": f"{vt}/domains/{indicator}",
                "hash": f"{vt}/files/{indicator}", "url": f"{vt}/search?query={indicator}"}
        resp = requests.get(urls.get(indicator_type, urls["url"]),
                            headers={"x-apikey": GTI_API_KEY}, timeout=30)

        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {}) if isinstance(resp.json().get("data"), dict) else {}
            result = {"indicator": indicator, "type": indicator_type,
                      "reputation": attrs.get("reputation", "N/A"),
                      "last_analysis_stats": attrs.get("last_analysis_stats", {}),
                      "tags": attrs.get("tags", [])}
            if indicator_type == "ip":
                result.update({"asn": attrs.get("asn"), "as_owner": attrs.get("as_owner"), "country": attrs.get("country")})
            elif indicator_type == "hash":
                result.update({"file_type": attrs.get("type_description"), "file_name": attrs.get("meaningful_name"),
                               "size": attrs.get("size"), "first_seen": attrs.get("first_submission_date")})
            return json.dumps(result)
        elif resp.status_code == 404:
            return json.dumps({"indicator": indicator, "result": "NOT_FOUND", "note": "May be novel/zero-day."})
        return json.dumps({"error": f"GTI [{resp.status_code}]"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def extract_iocs_from_detections(hours_back: int = 24) -> str:
    """
    Bulk extract all IOCs (IPs, domains, hashes, emails) from recent detections.
    Returns deduplicated sets for blocklist or Data Table population.
    """
    try:
        hours_back = min(max(1, hours_back), 168)
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = {"page_size": 1000, "start_time": start, "end_time": end}
        ips, domains, hashes, emails = set(), set(), set(), set()
        page_count = 0

        while True:
            resp = requests.post(f"{SECOPS_BASE_URL}/rules:listDetections",
                                 headers=_secops_headers(), json=payload, timeout=30)
            if resp.status_code != 200:
                break
            data = resp.json()
            page_count += 1
            for det in data.get("detections", []):
                for elem in det.get("collectionElements", []):
                    for ref in elem.get("references", []):
                        event = ref.get("event", {})
                        for field in ("target", "principal", "src"):
                            entity = event.get(field, {})
                            for ip in entity.get("ip", []):
                                ips.add(ip)
                            hostname = entity.get("hostname", "")
                            if hostname and "." in hostname:
                                domains.add(hostname.lower())
                            file_info = entity.get("file", {})
                            if file_info.get("sha256"):
                                hashes.add(file_info["sha256"].lower())
                            if file_info.get("md5"):
                                hashes.add(file_info["md5"].lower())
                            user = entity.get("user", {})
                            for email in user.get("email_addresses", []):
                                emails.add(email.lower())
            token = data.get("nextPageToken")
            if not token:
                break
            payload["page_token"] = token

        result = {
            "ips": sorted(ips), "domains": sorted(domains),
            "hashes": sorted(hashes), "emails": sorted(emails),
            "totals": {"ips": len(ips), "domains": len(domains), "hashes": len(hashes), "emails": len(emails)},
            "pages_processed": page_count,
        }
        logger.info(f"IOC extraction: {len(ips)} IPs, {len(domains)} domains, {len(hashes)} hashes, {len(emails)} emails")
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def vertex_ai_investigate(context: str, task: str = "Analyze and provide a threat assessment.", model: str = "gemini-2.0-flash") -> str:
    """Use Vertex AI (Gemini) to analyze security findings and generate investigation reports."""
    try:
        from google.cloud import aiplatform
        from vertexai.generative_models import GenerativeModel
        aiplatform.init(project=SECOPS_PROJECT_ID, location=SECOPS_REGION)
        prompt = f"""You are an expert security analyst in a Google SecOps environment.

TASK: {task}

SECURITY CONTEXT:
{context[:10000]}

Provide: 1) THREAT ASSESSMENT (severity + confidence) 2) KEY FINDINGS 3) ATTACK NARRATIVE 4) RECOMMENDED ACTIONS 5) DETECTION GAPS
Reference UDM fields, MITRE ATT&CK techniques, and Google SecOps capabilities."""

        response = GenerativeModel(model).generate_content(prompt)
        return json.dumps({"analysis": response.text, "model": model})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📋 DATA TABLE MANAGEMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def list_data_tables() -> str:
    """List all Data Tables in the SecOps instance."""
    try:
        resp = requests.get(f"{SECOPS_BASE_URL}/dataTables", headers=_secops_headers(), timeout=15)
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def get_data_table(table_name: str) -> str:
    """Read the contents of a specific Data Table."""
    try:
        resp = requests.get(f"{SECOPS_BASE_URL}/dataTables/{table_name}",
                            headers=_secops_headers(), timeout=15)
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def update_data_table(table_name: str, rows: list, description: str = "") -> str:
    """
    Update a Data Table with new rows. Overwrites existing content.
    Each row is a list of string values matching the table's column schema.
    Use for VIP lists, IOC blocklists, TI feeds, ASN exclusions, etc.
    """
    try:
        payload = {
            "name": table_name,
            "rows": [{"values": row if isinstance(row, list) else [row]} for row in rows],
        }
        if description:
            payload["description"] = description
        resp = requests.patch(f"{SECOPS_BASE_URL}/dataTables/{table_name}",
                              headers=_secops_headers(), json=payload, timeout=30)
        if resp.status_code == 200:
            logger.info(f"Data Table '{table_name}' updated: {len(rows)} rows")
            return json.dumps({"status": "success", "table": table_name, "rows_written": len(rows)})
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 🛡️ DETECTION MANAGEMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def list_rules(page_size: int = 100) -> str:
    """List all YARA-L rules in the SecOps instance with their enabled/disabled status."""
    try:
        resp = requests.get(f"{SECOPS_BASE_URL}/rules",
                            headers=_secops_headers(), params={"pageSize": page_size}, timeout=15)
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": f"API [{resp.status_code}]"})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def toggle_rule(rule_id: str, enabled: bool) -> str:
    """Enable or disable a YARA-L detection rule by its rule ID."""
    try:
        action = "enable" if enabled else "disable"
        resp = requests.post(f"{SECOPS_BASE_URL}/rules/{rule_id}:{action}",
                             headers=_secops_headers(), timeout=15)
        if resp.status_code == 200:
            logger.info(f"Rule {rule_id} {'enabled' if enabled else 'disabled'}")
            return json.dumps({"status": "success", "rule_id": rule_id, "enabled": enabled})
        return json.dumps({"error": f"API [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# 📧 EMAIL CONTAINMENT (Microsoft Graph)
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def purge_email_o365(target_mailbox: str, message_id: str, purge_type: str = "hardDelete") -> str:
    """
    Purge an email from an Office 365 mailbox using Microsoft Graph API.
    Uses the internet Message-ID header to locate the email, then executes a Hard or Soft Delete.

    Args:
        target_mailbox: The user's email address (e.g., user@company.com)
        message_id: The RFC 2822 Message-ID header value
        purge_type: "hardDelete" (bypasses trash) or "softDelete" (moves to trash)
    """
    try:
        token = _get_o365_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # Step 1: Find the email by internet Message-ID
        search_url = f"https://graph.microsoft.com/v1.0/users/{target_mailbox}/messages"
        params = {"$filter": f"internetMessageId eq '{message_id}'", "$select": "id,subject,from"}
        search_resp = requests.get(search_url, headers=headers, params=params, timeout=15)

        if search_resp.status_code != 200:
            return json.dumps({"error": f"Graph search failed [{search_resp.status_code}]", "detail": search_resp.text[:300]})

        messages = search_resp.json().get("value", [])
        if not messages:
            return json.dumps({"status": "not_found", "detail": f"No email with Message-ID '{message_id}' in {target_mailbox}"})

        internal_id = messages[0]["id"]
        subject = messages[0].get("subject", "unknown")

        # Step 2: Execute the purge
        if purge_type == "hardDelete":
            del_resp = requests.delete(f"https://graph.microsoft.com/v1.0/users/{target_mailbox}/messages/{internal_id}",
                                        headers=headers, timeout=15)
        else:
            del_resp = requests.post(f"https://graph.microsoft.com/v1.0/users/{target_mailbox}/messages/{internal_id}/move",
                                      headers=headers, json={"destinationId": "deleteditems"}, timeout=15)

        if del_resp.status_code in (200, 201, 204):
            logger.info(f"O365 purge: {purge_type} '{subject}' from {target_mailbox}")
            return json.dumps({"status": "purged", "mailbox": target_mailbox, "subject": subject, "purge_type": purge_type})
        return json.dumps({"error": f"Purge failed [{del_resp.status_code}]", "detail": del_resp.text[:300]})
    except RuntimeError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"O365 purge error: {e}"})


# ═══════════════════════════════════════════════════════════════
# 🔑 IDENTITY CONTAINMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def suspend_okta_user(user_email: str, clear_sessions: bool = True) -> str:
    """
    Suspend a user in Okta and optionally clear all active sessions.
    Used for compromised account containment — blocks new logins and kills existing tokens.
    """
    try:
        if not all([OKTA_DOMAIN, OKTA_API_TOKEN]):
            return json.dumps({"error": "Okta credentials not configured"})
        headers = {"Authorization": f"SSWS {OKTA_API_TOKEN}", "Content-Type": "application/json"}

        # Find user by email
        user_resp = requests.get(f"https://{OKTA_DOMAIN}/api/v1/users/{user_email}",
                                  headers=headers, timeout=15)
        if user_resp.status_code != 200:
            return json.dumps({"error": f"User not found [{user_resp.status_code}]"})

        user_id = user_resp.json()["id"]
        results = []

        # Suspend the user
        susp_resp = requests.post(f"https://{OKTA_DOMAIN}/api/v1/users/{user_id}/lifecycle/suspend",
                                   headers=headers, timeout=15)
        results.append(f"Suspend: {susp_resp.status_code}")

        # Clear sessions
        if clear_sessions:
            sess_resp = requests.delete(f"https://{OKTA_DOMAIN}/api/v1/users/{user_id}/sessions",
                                         headers=headers, timeout=15)
            results.append(f"Clear sessions: {sess_resp.status_code}")

        logger.info(f"Okta containment: {user_email} suspended, sessions cleared={clear_sessions}")
        return json.dumps({"status": "contained", "user": user_email, "actions": results})
    except Exception as e:
        return json.dumps({"error": f"Okta error: {e}"})


@app_mcp.tool()
def revoke_azure_ad_sessions(user_email: str) -> str:
    """Revoke all active sign-in sessions for an Azure AD / Entra ID user."""
    try:
        if not all([AZURE_AD_TENANT_ID, AZURE_AD_CLIENT_ID, AZURE_AD_CLIENT_SECRET]):
            return json.dumps({"error": "Azure AD credentials not configured"})

        # Get token
        token_resp = requests.post(
            f"https://login.microsoftonline.com/{AZURE_AD_TENANT_ID}/oauth2/v2.0/token",
            data={"client_id": AZURE_AD_CLIENT_ID, "client_secret": AZURE_AD_CLIENT_SECRET,
                  "scope": "https://graph.microsoft.com/.default", "grant_type": "client_credentials"},
            timeout=15,
        )
        token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Revoke sessions
        resp = requests.post(f"https://graph.microsoft.com/v1.0/users/{user_email}/revokeSignInSessions",
                              headers=headers, timeout=15)

        if resp.status_code == 200:
            logger.info(f"Azure AD sessions revoked for {user_email}")
            return json.dumps({"status": "revoked", "user": user_email})
        return json.dumps({"error": f"Revoke failed [{resp.status_code}]", "detail": resp.text[:300]})
    except Exception as e:
        return json.dumps({"error": f"Azure AD error: {e}"})


# ═══════════════════════════════════════════════════════════════
# ☁️ CLOUD CREDENTIAL CONTAINMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def revoke_aws_access_keys(target_user: str) -> str:
    """Disable all active AWS IAM access keys for a user. Stops leaked credential abuse."""
    try:
        if not all([AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY]):
            return json.dumps({"error": "AWS credentials not configured"})
        import boto3
        from botocore.exceptions import ClientError
        iam = boto3.client("iam", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
        disabled = []
        paginator = iam.get_paginator("list_access_keys")
        for page in paginator.paginate(UserName=target_user):
            for key in page["AccessKeyMetadata"]:
                if key["Status"] == "Active":
                    iam.update_access_key(UserName=target_user, AccessKeyId=key["AccessKeyId"], Status="Inactive")
                    disabled.append(key["AccessKeyId"])
        logger.info(f"AWS keys disabled for {target_user}: {disabled}")
        return json.dumps({"status": "contained", "user": target_user, "keys_disabled": disabled})
    except Exception as e:
        return json.dumps({"error": f"AWS IAM error: {e}"})


@app_mcp.tool()
def revoke_aws_sts_sessions(target_user: str) -> str:
    """
    Deny all pre-existing STS sessions for an AWS IAM user.
    Critical: disabling access keys does NOT invalidate already-assumed roles.
    This attaches an inline deny-all policy conditioned on token issue time.
    """
    try:
        if not all([AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY]):
            return json.dumps({"error": "AWS credentials not configured"})
        import boto3
        iam = boto3.client("iam", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*",
                           "Condition": {"DateLessThan": {"aws:TokenIssueTime": now}}}]
        })
        iam.put_user_policy(UserName=target_user, PolicyName="SOAR_Emergency_Session_Revocation", PolicyDocument=policy)
        logger.info(f"AWS STS sessions revoked for {target_user} (tokens before {now})")
        return json.dumps({"status": "sessions_revoked", "user": target_user, "cutoff": now})
    except Exception as e:
        return json.dumps({"error": f"AWS STS error: {e}"})


@app_mcp.tool()
def revoke_gcp_sa_keys(project_id: str, service_account_email: str) -> str:
    """Delete all user-managed keys for a GCP service account. Stops leaked SA key abuse."""
    try:
        token = get_adc_token()
        headers = {"Authorization": f"Bearer {token}"}
        resource = f"projects/{project_id}/serviceAccounts/{service_account_email}"
        keys_resp = requests.get(
            f"https://iam.googleapis.com/v1/{resource}/keys?keyTypes=USER_MANAGED",
            headers=headers, timeout=15,
        )
        if keys_resp.status_code != 200:
            return json.dumps({"error": f"List keys failed [{keys_resp.status_code}]"})
        deleted = []
        for key in keys_resp.json().get("keys", []):
            key_name = key["name"]
            del_resp = requests.delete(f"https://iam.googleapis.com/v1/{key_name}", headers=headers, timeout=15)
            if del_resp.status_code in (200, 204):
                deleted.append(key_name.split("/")[-1])
        logger.info(f"GCP SA keys deleted for {service_account_email}: {deleted}")
        return json.dumps({"status": "contained", "sa": service_account_email, "keys_deleted": deleted})
    except Exception as e:
        return json.dumps({"error": f"GCP IAM error: {e}"})


# ═══════════════════════════════════════════════════════════════
# 🖥️ ENDPOINT CONTAINMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def isolate_crowdstrike_host(hostname: str = "", device_id: str = "") -> str:
    """
    Network-isolate a host via CrowdStrike Falcon API.
    The host can still communicate with the CrowdStrike cloud for remote forensics
    but is completely disconnected from the internal network.

    Provide either hostname or device_id. If hostname, we look up the device_id first.
    """
    try:
        token = _get_crowdstrike_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # Look up device_id by hostname if needed
        if not device_id and hostname:
            search_resp = requests.get(
                f"{CS_BASE_URL}/devices/queries/devices/v1",
                headers=headers,
                params={"filter": f'hostname:"{hostname}"'},
                timeout=15,
            )
            if search_resp.status_code == 200:
                ids = search_resp.json().get("resources", [])
                if not ids:
                    return json.dumps({"error": f"No CrowdStrike device found for hostname '{hostname}'"})
                device_id = ids[0]
            else:
                return json.dumps({"error": f"Device search failed [{search_resp.status_code}]"})

        if not device_id:
            return json.dumps({"error": "Provide hostname or device_id"})

        # Execute containment
        contain_resp = requests.post(
            f"{CS_BASE_URL}/devices/entities/devices-actions/v2?action_name=contain",
            headers=headers,
            json={"ids": [device_id]},
            timeout=15,
        )

        if contain_resp.status_code == 202:
            logger.info(f"CrowdStrike: host {device_id} ({hostname}) isolated")
            return json.dumps({"status": "isolated", "device_id": device_id, "hostname": hostname})
        return json.dumps({"error": f"Containment failed [{contain_resp.status_code}]", "detail": contain_resp.text[:300]})
    except RuntimeError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"CrowdStrike error: {e}"})


# ═══════════════════════════════════════════════════════════════
# 📂 SOAR CASE MANAGEMENT
# ═══════════════════════════════════════════════════════════════


@app_mcp.tool()
def create_soar_case(
    title: str,
    description: str,
    priority: str = "MEDIUM",
    alert_source: str = "MCP_SERVER",
) -> str:
    """Create a new case in Google SecOps SOAR."""
    try:
        resp = requests.post(
            f"{SECOPS_BASE_URL}/cases",
            headers=_secops_headers(),
            json={
                "displayName": title,
                "description": description,
                "priority": priority.upper(),
                "alertSource": alert_source,
            },
            timeout=15,
        )
        if resp.status_code in (200, 201):
            logger.info(f"SOAR case created: {title}")
            return resp.text
        return json.dumps({"error": f"Case creation failed [{resp.status_code}]", "detail": resp.text[:500]})
    except Exception as e:
        return json.dumps({"error": str(e)})


@app_mcp.tool()
def update_soar_case(
    case_id: str,
    comment: str = "",
    priority: str = "",
    status: str = "",
    close_reason: str = "",
) -> str:
    """
    Update an existing SOAR case — add comments, change priority, or close.

    Args:
        case_id: The case identifier
        comment: Text to add to the case wall
        priority: New priority (CRITICAL, HIGH, MEDIUM, LOW)
        status: New status (OPEN, IN_PROGRESS, CLOSED)
        close_reason: Required when status=CLOSED
    """
    try:
        results = []

        if comment:
            resp = requests.post(
                f"{SECOPS_BASE_URL}/cases/{case_id}/comments",
                headers=_secops_headers(),
                json={"body": comment},
                timeout=15,
            )
            results.append(f"Comment: {resp.status_code}")

        if priority:
            resp = requests.patch(
                f"{SECOPS_BASE_URL}/cases/{case_id}",
                headers=_secops_headers(),
                json={"priority": priority.upper()},
                timeout=15,
            )
            results.append(f"Priority: {resp.status_code}")

        if status:
            body = {"status": status.upper()}
            if close_reason:
                body["closeReason"] = close_reason
            resp = requests.patch(
                f"{SECOPS_BASE_URL}/cases/{case_id}",
                headers=_secops_headers(),
                json=body,
                timeout=15,
            )
            results.append(f"Status: {resp.status_code}")

        logger.info(f"SOAR case {case_id} updated: {results}")
        return json.dumps({"status": "updated", "case_id": case_id, "actions": results})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ═══════════════════════════════════════════════════════════════
# RUN SERVER
# ═══════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════
# STARLETTE APP WITH SSE TRANSPORT
# ═══════════════════════════════════════════════════════════════

from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse

sse = SseServerTransport("/messages/")

async def handle_sse(request: StarletteRequest):
    async with sse.connect_sse(
        request.scope, request.receive, request._send
    ) as streams:
        await app_mcp._mcp_server.run(
            streams[0], streams[1], app_mcp._mcp_server.create_initialization_options()
        )

async def handle_messages(request: StarletteRequest):
    await sse.handle_post_message(request.scope, request.receive, request._send)

async def health_check(request: StarletteRequest):
    health = {
        "status": "healthy",
        "server": "google-native-mcp",
        "version": "2.0.0",
        "tools": 22,
        "project": SECOPS_PROJECT_ID,
        "region": SECOPS_REGION,
        "integrations": {
            "gti": bool(GTI_API_KEY),
            "o365": bool(O365_CLIENT_ID),
            "okta": bool(OKTA_DOMAIN),
            "azure_ad": bool(AZURE_AD_CLIENT_ID),
            "aws": bool(AWS_ACCESS_KEY_ID),
            "crowdstrike": bool(CS_CLIENT_ID),
        },
    }
    return JSONResponse(health)

app = Starlette(
    routes=[
        Route("/health", endpoint=health_check),
        Route("/sse", endpoint=handle_sse),
        Mount("/messages", app=sse.handle_post_message),
    ]
)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
