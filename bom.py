# bom.py
import requests
from config import get_api_headers, get_dtrack_url

def upload_bom(project_uuid, bom_file_path, auto_create=False):
    """Uploads BOM file to Dependency-Track for the given project UUID."""
    url = f"{get_dtrack_url()}api/v1/bom"
    headers = get_api_headers(content_type=None)  # Content-Type will be determined by 'files' parameter
    with open(bom_file_path, 'rb') as bom_file:
        files = {
            'project': (None, project_uuid),
            'bom': (bom_file_path, bom_file, 'application/xml')
        }
        if auto_create:
            files['autoCreate'] = (None, 'true')
        response = requests.post(url, headers=headers, files=files)
        response.raise_for_status()
        return response.json()
