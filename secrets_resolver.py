"""Secret Manager resolver — procurement-grade secret handling.

Usage:
    from secrets_resolver import resolve

    GTI_API_KEY = resolve("GTI_API_KEY")

Resolution order:
    1. If the env var's value starts with `sm://`, treat it as a Secret Manager
       reference and fetch it. Supported forms:
         sm://<secret-name>                      (uses SECOPS_PROJECT_ID)
         sm://<project>/<secret-name>
         sm://<project>/<secret-name>/<version>  (default version: "latest")
    2. Otherwise return the plain env value (local dev / docker-compose case).
    3. If the env var is unset, return default.

Cloud Run users can skip this module entirely by mounting secrets via
`--set-secrets GTI_API_KEY=gti-api-key:latest` — the resolved env var then
contains the plaintext, and this module just passes it through.

But when the env var is a reference (say, when running under Kubernetes or
a home-grown deploy), this module fetches it explicitly, caches it, and
redacts it from logs.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Dict, Optional

log = logging.getLogger("mcp-boss.secrets")

_CACHE: Dict[str, str] = {}
_LOCK = threading.Lock()
_SCHEME = "sm://"


def _parse(ref: str) -> tuple[str, str, str]:
    """Parse `sm://[project/]name[/version]`. Returns (project, name, version)."""
    path = ref[len(_SCHEME):]
    parts = path.split("/")
    default_project = os.environ.get("SECOPS_PROJECT_ID", "")
    if len(parts) == 1:
        return default_project, parts[0], "latest"
    if len(parts) == 2:
        return parts[0], parts[1], "latest"
    return parts[0], parts[1], parts[2]


def _fetch_from_gsm(project: str, name: str, version: str) -> Optional[str]:
    try:
        from google.cloud import secretmanager  # type: ignore
    except ImportError:
        log.warning("google-cloud-secret-manager not installed; cannot resolve sm:// refs")
        return None
    if not project:
        log.error("sm:// reference needs SECOPS_PROJECT_ID or explicit project in ref")
        return None
    try:
        client = secretmanager.SecretManagerServiceClient()
        resource = f"projects/{project}/secrets/{name}/versions/{version}"
        response = client.access_secret_version(request={"name": resource})
        return response.payload.data.decode("utf-8")
    except Exception as e:
        log.error("Failed to resolve %s/%s@%s: %s", project, name, version, e)
        return None


def resolve(env_name: str, default: str = "") -> str:
    """Get the value of env var `env_name`, resolving sm:// references.

    Thread-safe and cached. Returns `default` if unset or resolution fails.
    """
    raw = os.environ.get(env_name, default)
    if not raw or not raw.startswith(_SCHEME):
        return raw

    with _LOCK:
        cached = _CACHE.get(raw)
        if cached is not None:
            return cached
    project, name, version = _parse(raw)
    value = _fetch_from_gsm(project, name, version)
    if value is None:
        return default
    with _LOCK:
        _CACHE[raw] = value
    log.info("Resolved %s from Secret Manager (%s/%s@%s)", env_name, project, name, version)
    return value


def clear_cache() -> None:
    """Drop cached secret values. Call after rotation."""
    with _LOCK:
        _CACHE.clear()


def is_reference(env_name: str) -> bool:
    """True if the given env var holds an sm:// reference (not a plaintext secret)."""
    return os.environ.get(env_name, "").startswith(_SCHEME)
