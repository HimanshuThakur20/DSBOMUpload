# config.py
import os
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_dtrack_url():
    """Gets the Dependency-Track base URL from the environment."""
    url = os.getenv("DTRACK_URL")
    if not url:
        raise ValueError("Dependency-Track URL not set. Please set DTRACK_URL in environment variables.")
    if not url.endswith("/"):
        url += "/"
    return url

def get_ssl_verify():
    """Returns whether to verify SSL certificates. Set DTRACK_SSL_VERIFY=false to disable."""
    return os.getenv("DTRACK_SSL_VERIFY", "false").lower() != "false"

def get_api_key():
    """Gets the Dependency-Track API key from the environment."""
    api_key = os.getenv("DTRACK_API_KEY")
    if not api_key:
        raise ValueError("API Key not set. Please set DTRACK_API_KEY in environment variables.")
    return api_key

def get_api_headers(content_type="application/json"):
    """Returns the headers for HTTP requests to Dependency-Track."""
    return {
        "X-Api-Key": get_api_key(),
        "Content-Type": content_type
    }
