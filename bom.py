# bom.py

import requests
from rich.console import Console
import os

console = Console()

def upload_bom(project_uuid, bom_file):
    api_url = os.getenv("DTRACK_URL", "http://localhost:8081")
    api_key = os.getenv("DTRACK_API_KEY")

    url = f"{api_url}/api/v1/bom"
    headers = {"X-Api-Key": api_key}

    with open(bom_file, "rb") as f:
        files = {"bom": f}
        data = {"project": project_uuid}

        console.print(f"[cyan]Uploading BOM to project UUID:[/cyan] {project_uuid}")
        response = requests.post(url, headers=headers, files=files, data=data)

    if response.status_code == 200:
        console.print("[green]✅ BOM uploaded successfully![/green]")
    else:
        console.print(f"[red]❌ Upload failed: HTTP {response.status_code}[/red]")
        console.print(f"[yellow]Response text:[/yellow] {response.text}")
        response.raise_for_status()
