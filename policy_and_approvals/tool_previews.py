"""Dry-run preview builders and entity extractors for each destructive tool.

Imported by main.py to wire the @gate.guard() decorator. Keeping these out of
main.py keeps the policy subsystem self-contained.
"""

from __future__ import annotations

from typing import Any, Dict

from .models import DryRunPreview


# ─────────────────────────────────── O365 email purge ────────────────────────

def preview_purge_email_o365(target_mailbox: str, message_id: str, purge_type: str = "hardDelete", **_: Any) -> DryRunPreview:
    return DryRunPreview(
        tool_name="purge_email_o365",
        args={"target_mailbox": target_mailbox, "message_id": message_id, "purge_type": purge_type},
        entities={"mailbox": target_mailbox, "message_id": message_id, "action": purge_type},
        side_effects=[
            f"{purge_type} email with Message-ID {message_id!r} from {target_mailbox}",
        ],
        reversible=(purge_type == "softDelete"),
        reversal_hint="softDelete lands in Deleted Items and is restorable via Graph" if purge_type == "softDelete" else "",
    )


def entities_purge_email_o365(target_mailbox: str, message_id: str, purge_type: str = "hardDelete", **_: Any) -> Dict[str, Any]:
    return {"mailbox": target_mailbox, "message_id": message_id, "action": purge_type}


# ─────────────────────────────────── Okta suspend ────────────────────────────

def preview_suspend_okta_user(user_email: str, clear_sessions: bool = True, **_: Any) -> DryRunPreview:
    effects = [f"Suspend Okta user {user_email}"]
    if clear_sessions:
        effects.append(f"Clear all active sessions for {user_email}")
    return DryRunPreview(
        tool_name="suspend_okta_user",
        args={"user_email": user_email, "clear_sessions": clear_sessions},
        entities={"user_email": user_email},
        side_effects=effects,
        reversible=True,
        reversal_hint="POST /api/v1/users/{id}/lifecycle/unsuspend to restore",
    )


def entities_suspend_okta_user(user_email: str, **_: Any) -> Dict[str, Any]:
    return {"user_email": user_email}


# ─────────────────────────────────── Azure AD revoke ─────────────────────────

def preview_revoke_azure_ad_sessions(user_email: str, **_: Any) -> DryRunPreview:
    return DryRunPreview(
        tool_name="revoke_azure_ad_sessions",
        args={"user_email": user_email},
        entities={"user_email": user_email},
        side_effects=[f"Revoke all Azure AD sign-in sessions for {user_email}"],
        reversible=True,
        reversal_hint="User can re-authenticate; revocation does not disable the account",
    )


def entities_revoke_azure_ad_sessions(user_email: str, **_: Any) -> Dict[str, Any]:
    return {"user_email": user_email}


# ─────────────────────────────────── AWS key / STS revoke ───────────────────

def preview_revoke_aws_access_keys(target_user: str, **_: Any) -> DryRunPreview:
    return DryRunPreview(
        tool_name="revoke_aws_access_keys",
        args={"target_user": target_user},
        entities={"aws_user": target_user},
        side_effects=[f"Set status=Inactive on all active AWS IAM access keys for user {target_user}"],
        reversible=True,
        reversal_hint="aws iam update-access-key --status Active to restore",
    )


def entities_revoke_aws_access_keys(target_user: str, **_: Any) -> Dict[str, Any]:
    return {"aws_user": target_user}


def preview_revoke_aws_sts_sessions(target_user: str, **_: Any) -> DryRunPreview:
    return DryRunPreview(
        tool_name="revoke_aws_sts_sessions",
        args={"target_user": target_user},
        entities={"aws_user": target_user},
        side_effects=[
            f"Attach inline policy denying all STS sessions predating now for {target_user}"
        ],
        reversible=True,
        reversal_hint="Detach the AWSRevokeOlderSessions inline policy",
    )


def entities_revoke_aws_sts_sessions(target_user: str, **_: Any) -> Dict[str, Any]:
    return {"aws_user": target_user}


# ─────────────────────────────────── GCP SA keys ─────────────────────────────

def preview_revoke_gcp_sa_keys(project_id: str = "", service_account_email: str = "", **_: Any) -> DryRunPreview:
    return DryRunPreview(
        tool_name="revoke_gcp_sa_keys",
        args={"project_id": project_id, "service_account_email": service_account_email},
        entities={"gcp_project": project_id, "service_account": service_account_email},
        side_effects=[
            f"Delete all USER_MANAGED keys on service account {service_account_email or '(all SAs)'} in project {project_id or '(default)'}",
        ],
        reversible=False,
        reversal_hint="Keys are permanently deleted. New keys must be generated.",
    )


def entities_revoke_gcp_sa_keys(project_id: str = "", service_account_email: str = "", **_: Any) -> Dict[str, Any]:
    return {"gcp_project": project_id, "service_account": service_account_email}


# ─────────────────────────────────── CrowdStrike isolate ─────────────────────

def preview_isolate_crowdstrike_host(hostname: str = "", device_id: str = "", **_: Any) -> DryRunPreview:
    target = hostname or device_id or "(unspecified)"
    return DryRunPreview(
        tool_name="isolate_crowdstrike_host",
        args={"hostname": hostname, "device_id": device_id},
        entities={"host": target},
        side_effects=[f"Network-isolate host {target} via CrowdStrike Falcon containment"],
        reversible=True,
        reversal_hint="POST /devices/entities/devices-actions/v2?action_name=lift_containment",
    )


def entities_isolate_crowdstrike_host(hostname: str = "", device_id: str = "", **_: Any) -> Dict[str, Any]:
    return {"host": hostname or device_id}


# ─────────────────────────────────── Rule toggle ─────────────────────────────

def preview_toggle_rule(rule_id: str, action: str = "", enabled: bool = True, **_: Any) -> DryRunPreview:
    # The real tool takes either `action` ("enable"/"disable") or `enabled` (bool).
    act = action or ("enable" if enabled else "disable")
    return DryRunPreview(
        tool_name="toggle_rule",
        args={"rule_id": rule_id, "action": act},
        entities={"rule_id": rule_id, "action": act},
        side_effects=[f"{act.capitalize()} YARA-L rule {rule_id}"],
        reversible=True,
        reversal_hint="Re-run toggle_rule with the opposite action",
    )


def entities_toggle_rule(rule_id: str, action: str = "", enabled: bool = True, **_: Any) -> Dict[str, Any]:
    act = action or ("enable" if enabled else "disable")
    return {"rule_id": rule_id, "action": act}


# ─────────────────────────────── Bulk case close ─────────────────────────────

def preview_bulk_close_case(case_ids, reason: str = "", **_: Any) -> DryRunPreview:
    ids = case_ids if isinstance(case_ids, list) else [case_ids]
    return DryRunPreview(
        tool_name="secops_execute_bulk_close_case",
        args={"case_ids": ids, "reason": reason},
        entities={"case_count": len(ids)},
        side_effects=[f"Close {len(ids)} SOAR cases: {ids[:5]}{'...' if len(ids) > 5 else ''}"],
        reversible=True,
        reversal_hint="Reopen via secops_update_case",
    )


def entities_bulk_close_case(case_ids, **_: Any) -> Dict[str, Any]:
    ids = case_ids if isinstance(case_ids, list) else [case_ids]
    return {"case_count": len(ids)}
