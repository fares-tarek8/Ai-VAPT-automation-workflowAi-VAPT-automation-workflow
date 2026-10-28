import ipaddress
import os
from typing import Literal

Mode = Literal["ctf", "assessment"]

# Actions that the agent may request.
CTF_ACTIONS = {"discover", "enumerate", "verify"}
ASSESSMENT_ACTIONS = {"discover", "enumerate", "assess", "verify"}


class ScopeError(ValueError):
    """Raised when a target or action is outside the permitted scope."""


def get_allowed_networks():
    raw = os.environ.get("TARGET_ALLOWLIST", "").strip()

    if not raw:
        raise ScopeError(
            "TARGET_ALLOWLIST is missing. No targets are authorized."
        )

    networks = []

    for item in raw.split(","):
        item = item.strip()

        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ScopeError(
                f"Invalid network entry in TARGET_ALLOWLIST: {item}"
            ) from exc

    return networks


def validate_target(
    target: str,
    mode: Mode,
    action: str,
) -> dict:
    """Validate a target and action without performing any network activity."""

    if mode not in ("ctf", "assessment"):
        raise ScopeError("Mode must be 'ctf' or 'assessment'.")

    if mode == "ctf":
        permitted_actions = CTF_ACTIONS
    else:
        permitted_actions = ASSESSMENT_ACTIONS

    if action not in permitted_actions:
        raise ScopeError(
            f"Action '{action}' is not permitted in {mode} mode."
        )

    try:
        address = ipaddress.ip_address(target.strip())
    except ValueError as exc:
        raise ScopeError(
            "Target must be a single IPv4 or IPv6 address."
        ) from exc

    networks = get_allowed_networks()

    if not any(
        address.version == network.version and address in network
        for network in networks
    ):
        raise ScopeError(
            f"Target {address} is outside the configured allowlist."
        )

    return {
        "target": str(address),
        "mode": mode,
        "action": action,
        "scope_status": "allowed",
        "execution_performed": False,
    }
