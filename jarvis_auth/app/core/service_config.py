"""Service URL discovery for outbound best-effort calls.

jarvis-auth historically called no other services. Account deletion adds a
best-effort downstream purge fan-out to jarvis-command-center and
jarvis-notifications, so we need to resolve their URLs.

Resolution order per service:
1. Explicit env override (JARVIS_COMMAND_CENTER_URL / JARVIS_NOTIFICATIONS_URL).
2. config-service discovery (GET {JARVIS_CONFIG_URL}/services).
3. None (caller treats an unresolved service as "not deployed in this install").
"""

import logging
import os
from urllib.parse import urlparse

import httpx

from jarvis_auth.app.core import settings as settings_module

logger = logging.getLogger(__name__)

# Service names as registered in jarvis-config-service.
COMMAND_CENTER_SERVICE = "jarvis-command-center"
NOTIFICATIONS_SERVICE = "jarvis-notifications"


def _env_override(service_name: str) -> str | None:
    """Explicit env override for a service URL, if configured."""
    settings = settings_module.settings
    if service_name == COMMAND_CENTER_SERVICE:
        return settings.command_center_url
    if service_name == NOTIFICATIONS_SERVICE:
        return settings.notifications_url
    return None


def _style_params(config_url: str) -> dict[str, str]:
    """Mirror jarvis-config-client so config-service returns reachable URLs.

    Without a style param config-service returns localhost URLs, which are
    unreachable from inside a container. JARVIS_CONFIG_URL_STYLE=dockerized (or
    a host.docker.internal config URL) yields host.docker.internal URLs; remote
    yields the config host's address.
    """
    url_style = os.getenv("JARVIS_CONFIG_URL_STYLE", "").strip().lower()
    params: dict[str, str] = {}
    if url_style == "remote":
        params["style"] = "remote"
        host = urlparse(config_url).hostname
        if host and host not in ("localhost", "127.0.0.1"):
            params["remote_host"] = host
    elif url_style == "dockerized" or "host.docker.internal" in config_url:
        params["style"] = "dockerized"
    return params


def _discover_from_config(service_name: str) -> str | None:
    """Resolve a service URL from config-service's /services registry."""
    config_url = settings_module.settings.config_url
    if not config_url:
        return None
    try:
        resp = httpx.get(
            f"{config_url.rstrip('/')}/services",
            params=_style_params(config_url),
            timeout=5.0,
        )
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning(
            "Failed to query config-service for %s: %s", service_name, exc
        )
        return None

    # The /services payload may be a list of records or a dict keyed by name.
    records: list[dict] = []
    if isinstance(data, dict):
        services = data.get("services", data)
        if isinstance(services, dict):
            for name, entry in services.items():
                if isinstance(entry, dict):
                    records.append({"name": name, **entry})
        elif isinstance(services, list):
            records = [r for r in services if isinstance(r, dict)]
    elif isinstance(data, list):
        records = [r for r in data if isinstance(r, dict)]

    for record in records:
        if record.get("name") == service_name:
            url = record.get("url") or record.get("base_url")
            if url:
                return str(url).rstrip("/")
    return None


def get_service_url(service_name: str) -> str | None:
    """Resolve a downstream service URL, or None if it can't be found."""
    override = _env_override(service_name)
    if override:
        return override.rstrip("/")

    discovered = _discover_from_config(service_name)
    if discovered:
        return discovered

    logger.info(
        "Could not resolve URL for %s; treating as not deployed", service_name
    )
    return None


def get_command_center_url() -> str | None:
    """Get jarvis-command-center URL, or None if not resolvable."""
    return get_service_url(COMMAND_CENTER_SERVICE)


def get_notifications_url() -> str | None:
    """Get jarvis-notifications URL, or None if not resolvable."""
    return get_service_url(NOTIFICATIONS_SERVICE)
