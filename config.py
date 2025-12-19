# config.py
import os


def get_dtrack_url():
    """Gets the Dependency-Track base URL from the environment."""
    url = os.getenv("DTRACK_URL")
    if not url:
        raise ValueError("Dependency-Track URL not set. Please set DTRACK_URL.")
    if not url.endswith("/"):
        url += "/"
    return url


def get_api_key():
    """Gets the Dependency-Track API key from the environment."""
    api_key = os.getenv("DTRACK_API_KEY")
    if not api_key:
        raise ValueError("API Key not set. Please set DTRACK_API_KEY.")
    return api_key


def get_api_headers(content_type="application/json"):
    return {
        "X-Api-Key": get_api_key(),
        "Content-Type": content_type
    }


# ==========================================================
# AUTOMATION CONFIG
# ==========================================================

def get_automation_root() -> str:
    """
    Returns the root directory for SBOM automation.

    Environment variable:
        SBOM_AUTOMATION_ROOT

    Hard fail if missing or invalid.
    """
    root = os.getenv("SBOM_AUTOMATION_ROOT")
    if not root:
        raise RuntimeError(
            "SBOM_AUTOMATION_ROOT is not set. "
            "Please set it to the root folder containing application directories."
        )

    root = os.path.abspath(root)

    if not os.path.exists(root):
        raise RuntimeError(f"SBOM automation root does not exist: {root}")

    if not os.path.isdir(root):
        raise RuntimeError(f"SBOM automation root is not a directory: {root}")

    return root
