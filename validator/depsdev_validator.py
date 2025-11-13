# depsdev_validator.py

import requests
from rich.console import Console

console = Console()

DEPSDEV_BASE = "https://api.deps.dev/v3alpha/purl/"

def check_package_with_depsdev(purl):
    """
    Query deps.dev to validate package existence & version.
    Returns tuple: (pass, message)
    """
    url = DEPSDEV_BASE + purl

    try:
        response = requests.get(url, timeout=15)

        if response.status_code == 404:
            return False, f"Package not found in deps.dev: {purl}"

        if response.status_code != 200:
            return False, f"deps.dev returned HTTP {response.status_code} for {purl}"

        data = response.json()

        # Extract latest license info if available
        licenses = data.get("installed", {}).get("licenses", [])
        version = data.get("versionKey", {}).get("version", "unknown")

        return True, f"Package exists (version: {version}, licenses: {licenses})"

    except Exception as e:
        return False, f"deps.dev lookup error for {purl}: {e}"


def extract_purls(format_type, bom_data):
    """
    Extract PURLs from BOM (JSON or XML)
    """
    purls = []

    if format_type == "json":
        for comp in bom_data.get("components", []):
            p = comp.get("purl")
            if p:
                purls.append(p)

    else:
        # XML
        for comp in bom_data.findall(".//{*}component"):
            p_tag = comp.find("{*}purl")
            if p_tag is not None and p_tag.text:
                purls.append(p_tag.text)

    return purls


def perform_depsdev_validation(format_type, bom_data):
    """
    Validate all PURLs using deps.dev
    Returns list of tuples like:
        [("pkg:pypi/requests@2.31.0", True, "OK"), ...]
    """
    results = []

    purls = extract_purls(format_type, bom_data)
    if not purls:
        return [("No PURLs found", False, "BOM has no valid package URLs")]

    for p in purls:
        ok, msg = check_package_with_depsdev(p)
        results.append((p, ok, msg))

    return results
