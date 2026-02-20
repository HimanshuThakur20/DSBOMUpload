# bom.py

import requests
from rich.console import Console
from config import get_api_headers, get_dtrack_url

console = Console()


def upload_bom(project_uuid, bom_file):
    """
    Upload a CycloneDX XML BOM file to Dependency-Track.
    This version sends the BOM using multipart/form-data as supported by /api/v1/bom.
    """
    url = f"{get_dtrack_url()}api/v1/bom"
    headers = get_api_headers()
    # ❗ Remove content-type from headers — requests will set the correct multipart boundary
    headers.pop("Content-Type", None)

    with open(bom_file, "rb") as f:
        files = {
            "bom": (bom_file, f, "application/xml")
        }
        data = {
            "project": project_uuid
        }

        console.print(f"[cyan]Uploading BOM to project UUID:[/cyan] {project_uuid}")
        response = requests.post(url, headers=headers, files=files, data=data)

    if response.status_code != 200:
        console.print(f"[red]❌ Upload failed: HTTP {response.status_code}[/red]")
        console.print(f"[yellow]Response text:[/yellow] {response.text}")
        response.raise_for_status()

