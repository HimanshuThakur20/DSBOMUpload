# project.py

import requests
from config import get_api_headers, get_dtrack_url, get_ssl_verify
from packaging import version

def get_projects():
    """
    Fetch all projects from Dependency-Track.
    """
    url = f"{get_dtrack_url()}api/v1/project"
    response = requests.get(url, headers=get_api_headers(), verify=get_ssl_verify())
    
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Could not fetch projects. Status code: {response.status_code}")
        return []

def find_project(projects, name, version_str):
    """
    Find a specific project by name and version.
    """
    for project in projects:
        if project['name'] == name and project['version'] == version_str:
            return project
    return None

def create_project(name, version_str):
    """
    Create a new project in Dependency-Track.
    """
    url = f"{get_dtrack_url()}api/v1/project"
    payload = {
        "name": name,
        "version": version_str,
        "active": True,
        "classifier": "APPLICATION"
    }
    response = requests.put(url, json=payload, headers=get_api_headers(), verify=get_ssl_verify())
    
    if response.status_code in [200, 201]:
        return response.json()
    else:
        print(f"Error: Could not create project. Status code: {response.status_code}")
        print(response.text)
        return None

def get_version_restriction(projects, name, version_str):
    """
    Checks if a project with the same version already exists.
    Returns True if already exists (i.e. upload should be restricted).
    """
    project_exists = find_project(projects, name, version_str)
    if project_exists:
        return True
    return False

def get_or_create_project(name, version_str):
    """
    Get a project by name and version. If it doesn't exist, create it.
    Restrict upload if the same version already exists.
    """
    projects = get_projects()

    if get_version_restriction(projects, name, version_str):
        print(f"Error: A project named '{name}' with version '{version_str}' already exists.")
        print("Please use a different version or delete the existing one.")
        return None

    print(f"Creating new project '{name}' with version '{version_str}'...")
    return create_project(name, version_str)

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
        return sorted(versions)[-1]


def get_latest_version_projects():
    """
    Returns a list of projects with only the latest version for each project name.
    
    Returns:
        List of project objects representing the latest version of each unique project.
    """
    projects = get_projects()
    if not projects:
        return []
    
    # Group projects by name
    project_groups = {}
    for p in projects:
        name = p.get("name", "")
        if name not in project_groups:
            project_groups[name] = []
        project_groups[name].append(p)
    
    # Get latest version for each project name
    latest_projects = []
    for name, versions in project_groups.items():
        if len(versions) == 1:
            latest_projects.append(versions[0])
        else:
            # Try to parse versions and get the latest
            try:
                latest = max(versions, key=lambda p: version.parse(p.get("version", "0")))
            except Exception:
                # Fallback to string sorting
                latest = max(versions, key=lambda p: p.get("version", ""))
            latest_projects.append(latest)
    
    return latest_projects
