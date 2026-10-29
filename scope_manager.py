import ipaddress
import socket
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

def get_allowed_hosts():
    raw = os.environ.get("TARGET_HOST_ALLOWLIST", "").strip()

    if not raw:
        return set()

    return {
        host.strip().lower().rstrip(".")
        for host in raw.split(",")
        if host.strip()
    }

def resolve_hostname(hostname):
    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise ScopeError(
            f"DNS resolution failed for {hostname}"
        ) from exc

    addresses = {
        str(ipaddress.ip_address(result[4][0]))
        for result in results
    }

    if not addresses:
        raise ScopeError("DNS returned no IP addresses.")

    return sorted(addresses)


def validate_resolved_ips(hostname, addresses):
    if not addresses:
        raise ScopeError("DNS returned no IP addresses.")

    for ip in addresses:
        address = ipaddress.ip_address(ip)

        if not address.is_global:
            raise ScopeError(
                f"Hostname {hostname} resolves to a "
                f"non-public IP address: {ip}"
            )

    return addresses


def validate_hostname_destination(hostname):
    hostname = hostname.strip().lower().rstrip(".")

    if hostname not in get_allowed_hosts():
        raise ScopeError(
            f"Hostname {hostname} is outside the configured allowlist."
        )

    addresses = resolve_hostname(hostname)

    validated_addresses = validate_resolved_ips(
        hostname,
        addresses
    )

    return {
        "hostname": hostname,
        "ip": validated_addresses[0]
    }



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


        target = target.strip().lower()

    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        allowed_hosts = get_allowed_hosts()

        if target not in allowed_hosts:
            raise ScopeError(
                f"Hostname {target} is outside the configured allowlist."
            )

        raise ScopeError(
            "Hostname is authorized, but safe DNS and connection "
            "validation is not implemented yet."
        )

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
