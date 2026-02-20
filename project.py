# project.py

import requests
import csv
from packaging import version as pkg_version
from config import get_api_headers, get_dtrack_url, get_ssl_verify

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


def find_project(projects, name, version):
    """
    Find a specific project by name and version.
    """
    for project in projects:
        if project['name'] == name and project['version'] == version:
            return project
    return None


def create_project(name, version):
    """
    Create a new project in Dependency-Track.
    """
    url = f"{get_dtrack_url()}api/v1/project"
    payload = {
        "name": name,
        "version": version,
        "active": True,
        "classifier": "APPLICATION"
    }
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


def get_or_create_project(name, version):
    """
    Get a project by name and version. If it doesn't exist, create it.
    Restrict upload if the same version already exists.
    """
    projects = get_projects()

    # Restrict uploading to same version
    if get_version_restriction(projects, name, version):
        print(f"Error: A project named '{name}' with version '{version}' already exists.")
        print("Please use a different version or delete the existing one.")
        return None

    print(f"Creating new project '{name}' with version '{version}'...")
    return create_project(name, version)

def get_latest_version(project_name):
    """
    Returns the latest version string for a given project name.
    """
    projects = get_projects()
    versions = [p["version"] for p in projects if p["name"] == project_name]
    if not versions:
        return None
    try:
        return str(max(pkg_version.parse(v) for v in versions))
    except Exception:
        # fallback for non-semver
        return sorted(versions)[-1]


def get_latest_version_projects():
    """
    Returns a list of projects containing only the latest version of each project.
    """
    projects = get_projects()
    project_versions = {}
    
    for project in projects:
        name = project.get("name", "")
        version = project.get("version", "")
        
        if name not in project_versions:
            project_versions[name] = project
        else:
            try:
                current_ver = pkg_version.parse(project_versions[name].get("version", ""))
                new_ver = pkg_version.parse(version)
                if new_ver > current_ver:
                    project_versions[name] = project
            except Exception:
                # fallback for non-semver
                if version > project_versions[name].get("version", ""):
                    project_versions[name] = project
    
    return list(project_versions.values())


def get_project_component_count(project_uuid):
    """
    Get the count of components for a specific project.
    """
    url = f"{get_dtrack_url()}api/v1/component/project/{project_uuid}"
    response = requests.get(url, headers=get_api_headers(), verify=get_ssl_verify())
    
    if response.status_code == 200:
        # The API returns a list of components
        return len(response.json())
    else:
        # Try getting count from header if available
        total = response.headers.get("X-Total-Count", "0")
        try:
            return int(total)
        except ValueError:
            return 0


def extract_ria_id(tags):
    """
    Extract the RIA ID from project tags.
    RIA IDs start with 'ria' (case-insensitive).
    """
    if not tags:
        return ""
    
    for tag in tags:
        tag_name = tag.get("name", "") if isinstance(tag, dict) else str(tag)
        if tag_name.lower().startswith("ria"):
            return tag_name
    return ""


def export_projects_to_csv(output_file="projects.csv", latest_only=False, max_tags=10):
    """
    Export all projects with tags as separate columns to a CSV file.
    
    Args:
        output_file: Path to the output CSV file
        latest_only: If True, export only the latest version of each project
        max_tags: Maximum number of tag columns to include
    
    Returns:
        Number of projects exported
    """
    if latest_only:
        projects = get_latest_version_projects()
    else:
        projects = get_projects()
    
    if not projects:
        print("No projects found to export.")
        return 0
    
    # Define headers with tag columns, ria_id and component_count
    tag_headers = [f"tag{i}" for i in range(1, max_tags + 1)]
    headers = ["uuid", "name", "version", "classifier", "active", "lastBomImport", "ria_id", "component_count"] + tag_headers
    
    rows = []
    total = len(projects)
    for idx, project in enumerate(projects, 1):
        print(f"Processing project {idx}/{total}: {project.get('name', 'Unknown')}...", end="\r")
        
        # Extract project tags
        tags = project.get("tags", [])
        tag_names = [tag.get("name", "") for tag in tags] if tags else []
        
        # Extract RIA ID from tags
        ria_id = extract_ria_id(tags)
        
        # Get component count for this project
        component_count = get_project_component_count(project.get("uuid", ""))
        
        # Pad tags to max_tags length
        while len(tag_names) < max_tags:
            tag_names.append("")
        
        row = {
            "uuid": project.get("uuid", ""),
            "name": project.get("name", ""),
            "version": project.get("version", ""),
            "classifier": project.get("classifier", ""),
            "active": project.get("active", ""),
            "lastBomImport": project.get("lastBomImport", ""),
            "ria_id": ria_id,
            "component_count": component_count,
        }
        
        # Add tag columns
        for i, tag in enumerate(tag_names[:max_tags]):
            row[f"tag{i+1}"] = tag
        
        rows.append(row)
    
    print()  # New line after progress
    
    # Write to CSV
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"Exported {len(rows)} projects to {output_file}")
    return len(rows)
