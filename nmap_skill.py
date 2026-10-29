import subprocess
import re
from scope_manager import validate_target


def nmap_discovery(target):
    # Step 1: Check whether the target is allowed
    scope = validate_target(
        target=target,
        mode="assessment",
        action="discover"
    )

    # Step 2: Run a restricted Nmap scan
    result = subprocess.run(
        [
            "nmap",
            "-sT",
            "-sV",
            "-Pn",
            "-p", "22,80,443",
            "--max-retries", "1",
            "--host-timeout", "60s",
            target
        ],
        capture_output=True,
        text=True,
        timeout=70,
        check=False
    )

    # Step 3: Check for errors
    if result.returncode != 0:
        raise RuntimeError(
            f"Nmap failed: {result.stderr}"
        )


    # Remove unnecessary Nmap information
    clean_output = result.stdout

    clean_output = re.sub(
        r" \( https://nmap\.org \)",
        "",
        clean_output
    )

    clean_output = re.sub(
        r"Service detection performed\..*",
        "",
        clean_output
    )

    # Step 4: Return the scan results
    return {
        "target": target,
        "scope": scope,
        "scan_output": clean_output.strip()
    }
