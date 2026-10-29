import requests
import re
import urllib3
import ipaddress
from http.cookies import SimpleCookie
from scope_manager import (
    validate_target,
    validate_hostname_destination,
    get_allowed_hosts,
    resolve_hostname,
    validate_resolved_ips,
    ScopeError
)


def connect_to_validated_ip(hostname, ip, protocol):
    port = 443 if protocol == "https" else 80

    if protocol == "https":
        connection = urllib3.HTTPSConnectionPool(
            host=ip,
            port=port,
            server_hostname=hostname,
            assert_hostname=hostname,
            cert_reqs="CERT_REQUIRED",
            maxsize=1,
            retries=False
        )
    else:
        connection = urllib3.HTTPConnectionPool(
            host=ip,
            port=port,
            maxsize=1,
            retries=False
        )

    try:
        response = connection.request(
            "GET",
            "/",
            headers={"Host": hostname},
            redirect=False,
            timeout=urllib3.Timeout(connect=5, read=10)
        )
        return response
    finally:
        connection.close()



def redact_cookie_values(headers):
    safe_headers = {}

    for name, value in headers.items():
        if name.lower() == "set-cookie":
            safe_headers[name] = re.sub(
                r"(?:(?<=^)|(?<=;))(\s*[^=;,\s]+\s*=\s*)[^;,\r\n]*",
                lambda match: match.group(1) + "[REDACTED]",
                value
            )
        else:
            safe_headers[name] = value

    return safe_headers



def http_enumeration(target, protocol="http"):
    # Step 1: Validate protocol
    if protocol not in ("http", "https"):
        raise ValueError("Protocol must be http or https")

    # Step 2: Determine whether target is an IP or hostname
    try:
        ipaddress.ip_address(target.strip())
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        scope = validate_target(
            target=target,
            mode="assessment",
            action="discover"
        )

        url = f"{protocol}://{target}"

        session = requests.Session()
        session.trust_env = False

        try:
            response = session.get(
                url,
                timeout=10,
                allow_redirects=False
            )

            status_code = response.status_code
            headers = dict(response.headers)

            cookie_results = []

            for cookie in response.cookies:
                cookie_results.append({
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                    "samesite": cookie.get_nonstandard_attr(
                        "SameSite", "Missing"
                    )
                })
        finally:
            session.close()

    else:
        # Step 3: Validate hostname and resolved IP
        destination = validate_hostname_destination(target)

        scope = {
            "target": destination["hostname"],
            "mode": "assessment",
            "action": "discover",
            "scope_status": "allowed",
            "execution_performed": False
        }

        # Step 4: Connect to the validated IP
        response = connect_to_validated_ip(
            hostname=destination["hostname"],
            ip=destination["ip"],
            protocol=protocol
        )

        status_code = response.status
        headers = dict(response.headers)

        # Step 5: Extract cookies from Set-Cookie headers
        cookie_results = []

        for raw_cookie in response.headers.getlist("Set-Cookie"):
            parsed = SimpleCookie()

            try:
                parsed.load(raw_cookie)
            except Exception:
                continue

            for name, cookie in parsed.items():
                cookie_results.append({
                    "name": name,
                    "secure": bool(cookie["secure"]),
                    "httponly": bool(cookie["httponly"]),
                    "samesite": cookie["samesite"] or "Missing"
                })

    # Step 6: Check security headers
    security_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options"
    ]

    security_header_results = {}

    for header in security_headers:
        security_header_results[header] = headers.get(
            header, "Missing"
        )

    # Step 7: Return results
    scope["execution_performed"] = True


    return {
        "scope": scope,
        "status_code": status_code,
        "headers": headers,
        "security_headers": security_header_results,
        "cookies": cookie_results
    }
