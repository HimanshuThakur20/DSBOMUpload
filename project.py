# project.py

import requests
import urllib3
from config import get_api_headers, get_dtrack_url

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_projects():
    """
    Fetch all projects from Dependency-Track.
    """
    url = f"{get_dtrack_url()}api/v1/project"
    response = requests.get(url, headers=get_api_headers(), verify=False)
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Could not fetch projects. Status code: {response.status_code}")
        return []


def find_project(projects, name, version):
    """
    Find a specific project by name and version.
    """
    for project in projects:
        if project['name'] == name and project['version'] == version:
            return project
    return None


def create_project(name, version, tags=None):
    """
    Create a new project in Dependency-Track.
    
    Args:
        name: Project name
        version: Project version
        tags: Optional list of tag names to add to the project
    """
    url = f"{get_dtrack_url()}api/v1/project"
    payload = {
        "name": name,
        "version": version,
        "active": True,
        "classifier": "APPLICATION"
    }
    
    # Add tags if provided
    if tags:
        payload["tags"] = [{"name": tag} for tag in tags]
    
    response = requests.put(url, json=payload, headers=get_api_headers())
    
    if response.status_code in [200, 201]:
        return response.json()
    else:
        print(f"Error: Could not create project. Status code: {response.status_code}")
        return None


def get_version_restriction(projects, name, version):
    """
    Checks if a project with the same version already exists.
    Returns True if already exists (i.e. upload should be restricted).
    """
    project_exists = find_project(projects, name, version)
    if project_exists:
        return True
    return False


def get_or_create_project(name, version, tags=None, allow_existing=False):
    """
    Get a project by name and version. If it doesn't exist, create it.
    Restrict upload if the same version already exists (unless allow_existing=True).
    
    Args:
        name: Project name
        version: Project version
        tags: Optional list of tag names to add to the project
        allow_existing: If True, return existing project instead of blocking
    """
    projects = get_projects()
    
    # Check if project with same version exists
    existing_project = find_project(projects, name, version)
    if existing_project:
        if allow_existing:
            return existing_project
        print(f"Error: A project named '{name}' with version '{version}' already exists.")
        print("Please use a different version or delete the existing one.")
        return None

    print(f"Creating new project '{name}' with version '{version}'...")
    return create_project(name, version, tags)

def get_latest_version(project_name):
    """
    Returns the latest version string for a given project name.
    """
    projects = get_projects()
    versions = [p["version"] for p in projects if p["name"] == project_name]
    if not versions:
        return None
    try:
        return str(max(version.parse(v) for v in versions))
    except Exception:
        # fallback for non-semver
        return sorted(versions)[-1]
