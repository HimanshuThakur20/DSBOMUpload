# bom.py

import os
import base64
import json
import requests
from rich.console import Console
from config import get_api_headers, get_dtrack_url

console = Console()


def upload_bom(project_uuid, bom_file):
    """
    Uploads a BOM (XML or JSON) file to Dependency-Track.
    Automatically encodes the file in base64 as required by the API.
    """
    url = f"{get_dtrack_url()}api/v1/bom?validate=false"
    headers = get_api_headers()

    if not os.path.exists(bom_file):
        console.print(f"[red]❌ Error: File not found:[/red] {bom_file}")
        return

    # Detect file type
    file_ext = os.path.splitext(bom_file)[1].lower()
    console.print(f"[cyan]Detected BOM format:[/cyan] {file_ext[1:].upper()}")

    # Read and base64 encode the file content
    with open(bom_file, "rb") as f:
        bom_data = f.read()
        bom_b64 = base64.b64encode(bom_data).decode("utf-8")

    # Prepare JSON payload for Dependency-Track API
    payload = {
        "project": project_uuid,
        "bom": bom_b64,
        "autoCreate": False
    }

    # Send as JSON request
    response = requests.put(url, headers={**headers, "Content-Type": "application/json"}, json=payload)

    if response.status_code != 200:
        console.print(f"[red]❌ Upload failed: HTTP {response.status_code}[/red]")
        console.print(f"[yellow]Response text:[/yellow] {response.text}")
        response.raise_for_status()

