# policy_violations.py

"""
Module for fetching and exporting policy violations from Dependency-Track.
"""

import requests
import json
import csv
import os
from datetime import datetime
from config import get_api_headers, get_dtrack_url, get_ssl_verify
from rich.console import Console
from rich.table import Table, box

console = Console()


def get_all_policy_violations(suppressed: bool = False):
    """
    Fetch all policy violations from Dependency-Track.
    
    Args:
        suppressed: If True, include suppressed violations. Default is False.
    
    Returns:
        List of policy violation objects or empty list on error.
    """
    url = f"{get_dtrack_url()}api/v1/violation"
    params = {"suppressed": str(suppressed).lower()}
    
    all_violations = []
    page_number = 1
    page_size = 100
    
    while True:
        params["pageNumber"] = page_number
        params["pageSize"] = page_size
        
        response = requests.get(url, headers=get_api_headers(), params=params, verify=get_ssl_verify())
        
        if response.status_code == 200:
            violations = response.json()
            if not violations:
                break
            all_violations.extend(violations)
            
            # Check if we got fewer than page_size, meaning we're done
            if len(violations) < page_size:
                break
            page_number += 1
        else:
            console.print(f"[red]Error:[/red] Could not fetch policy violations. Status code: {response.status_code}")
            console.print(f"Response: {response.text}")
            return []
    
    return all_violations


def get_project_policy_violations(project_uuid: str, suppressed: bool = False):
    """
    Fetch policy violations for a specific project.
    
    Args:
        project_uuid: The UUID of the project.
        suppressed: If True, include suppressed violations. Default is False.
    
    Returns:
        List of policy violation objects or empty list on error.
    """
    url = f"{get_dtrack_url()}api/v1/violation/project/{project_uuid}"
    params = {"suppressed": str(suppressed).lower()}
    
    all_violations = []
    page_number = 1
    page_size = 100
    
    while True:
        params["pageNumber"] = page_number
        params["pageSize"] = page_size
        
        response = requests.get(url, headers=get_api_headers(), params=params, verify=get_ssl_verify())
        
        if response.status_code == 200:
            violations = response.json()
            if not violations:
                break
            all_violations.extend(violations)
            
            if len(violations) < page_size:
                break
            page_number += 1
        else:
            console.print(f"[red]Error:[/red] Could not fetch project policy violations. Status code: {response.status_code}")
            console.print(f"Response: {response.text}")
            return []
    
    return all_violations


def get_component_policy_violations(component_uuid: str, suppressed: bool = False):
    """
    Fetch policy violations for a specific component.
    
    Args:
        component_uuid: The UUID of the component.
        suppressed: If True, include suppressed violations. Default is False.
    
    Returns:
        List of policy violation objects or empty list on error.
    """
    url = f"{get_dtrack_url()}api/v1/violation/component/{component_uuid}"
    params = {"suppressed": str(suppressed).lower()}
    
    response = requests.get(url, headers=get_api_headers(), params=params, verify=get_ssl_verify())
    
    if response.status_code == 200:
        return response.json()
    else:
        console.print(f"[red]Error:[/red] Could not fetch component policy violations. Status code: {response.status_code}")
        console.print(f"Response: {response.text}")
        return []


def enrich_violations_with_tags(violations: list, projects_with_tags: dict) -> list:
    """
    Enrich violations with project tags from a pre-fetched projects dictionary.
    
    Args:
        violations: List of policy violation objects.
        projects_with_tags: Dictionary mapping project UUID to project data with tags.
    
    Returns:
        List of violations with enriched tag information.
    """
    for violation in violations:
        component = violation.get("component", {})
        project = component.get("project", {})
        
        if not project:
            project = violation.get("project", {})
        
        proj_uuid = project.get("uuid", "")
        
        # If we have this project in our pre-fetched data with tags
        if proj_uuid and proj_uuid in projects_with_tags:
            proj_data = projects_with_tags[proj_uuid]
            tags = proj_data.get("tags", [])
            
            # Update the project in the violation with tags
            if "project" in component:
                component["project"]["tags"] = tags
            elif "project" in violation:
                violation["project"]["tags"] = tags
    
    return violations


def _flatten_violation(violation: dict, max_tags: int = 10) -> dict:
    """
    Flatten a policy violation object for export.
    
    Args:
        violation: Raw violation object from Dependency-Track API.
        max_tags: Maximum number of tag columns to include (default: 10).
    
    Returns:
        Flattened dictionary suitable for CSV/JSON export.
    """
    component = violation.get("component", {})
    policy_condition = violation.get("policyCondition", {})
    policy = policy_condition.get("policy", {})
    project = component.get("project", {})
    
    # Also check for project at violation level (some API responses have it there)
    if not project:
        project = violation.get("project", {})
    
    # Extract tags - tags is a list of tag objects with 'name' field
    tags_list = project.get("tags", [])
    tag_names = [tag.get("name", "") for tag in tags_list if tag.get("name")]
    
    result = {
        "violation_uuid": violation.get("uuid", ""),
        "violation_type": violation.get("type", ""),
        "violation_state": violation.get("analysis", {}).get("state") if violation.get("analysis") else "NOT_SET",
        "suppressed": violation.get("suppressed", False),
        
        # Policy details
        "policy_name": policy.get("name", ""),
        "policy_uuid": policy.get("uuid", ""),
        "policy_violation_state": policy.get("violationState", ""),
        
        # Policy condition details
        "condition_uuid": policy_condition.get("uuid", ""),
        "condition_subject": policy_condition.get("subject", ""),
        "condition_operator": policy_condition.get("operator", ""),
        "condition_value": policy_condition.get("value", ""),
        
        # Component details
        "component_uuid": component.get("uuid", ""),
        "component_name": component.get("name", ""),
        "component_version": component.get("version", ""),
        "component_group": component.get("group", ""),
        "component_purl": component.get("purl", ""),
        "component_cpe": component.get("cpe", ""),
        "component_license": component.get("license", ""),
        
        # Project details
        "project_uuid": project.get("uuid", ""),
        "project_name": project.get("name", ""),
        "project_version": project.get("version", ""),
    }
    
    # Add tag columns (tag1, tag2, tag3, etc.)
    for i in range(max_tags):
        tag_key = f"tag{i + 1}"
        result[tag_key] = tag_names[i] if i < len(tag_names) else ""
    
    return result


def display_violations_table(violations: list):
    """
    Display policy violations in a rich table format.
    
    Args:
        violations: List of policy violation objects.
    """
    if not violations:
        console.print("[yellow]No policy violations found.[/yellow]")
        return
    
    table = Table(
        title=f"Policy Violations ({len(violations)} total)",
        show_header=True,
        header_style="bold magenta",
        box=box.DOUBLE
    )
    
    table.add_column("Policy", style="cyan", no_wrap=True)
    table.add_column("Violation Type", style="yellow")
    table.add_column("Component", style="green")
    table.add_column("Version", style="white")
    table.add_column("Project", style="blue")
    table.add_column("State", style="red")
    
    for v in violations:
        component = v.get("component", {})
        policy_condition = v.get("policyCondition", {})
        policy = policy_condition.get("policy", {})
        project = component.get("project", {})
        
        analysis_state = "NOT_SET"
        if v.get("analysis"):
            analysis_state = v["analysis"].get("state", "NOT_SET")
        
        table.add_row(
            policy.get("name", "N/A"),
            v.get("type", "N/A"),
            component.get("name", "N/A"),
            component.get("version", "N/A"),
            project.get("name", "N/A"),
            analysis_state
        )
    
    console.print(table)


def export_violations_to_json(violations: list, output_path: str):
    """
    Export policy violations to a JSON file.
    
    Args:
        violations: List of policy violation objects.
        output_path: Path to the output JSON file.
    """
    flattened = [_flatten_violation(v) for v in violations]
    
    export_data = {
        "export_timestamp": datetime.now().isoformat(),
        "total_violations": len(violations),
        "violations": flattened
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    console.print(f"[green]✔ Exported {len(violations)} violations to:[/green] {output_path}")


def export_violations_to_csv(violations: list, output_path: str):
    """
    Export policy violations to a CSV file.
    
    Args:
        violations: List of policy violation objects.
        output_path: Path to the output CSV file.
    """
    if not violations:
        console.print("[yellow]No violations to export.[/yellow]")
        return
    
    flattened = [_flatten_violation(v) for v in violations]
    
    # Get all field names from the first flattened record
    fieldnames = list(flattened[0].keys())
    
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flattened)
    
    console.print(f"[green]✔ Exported {len(violations)} violations to:[/green] {output_path}")


def get_policies():
    """
    Fetch all policies from Dependency-Track.
    
    Returns:
        List of policy objects or empty list on error.
    """
    url = f"{get_dtrack_url()}api/v1/policy"
    
    response = requests.get(url, headers=get_api_headers(), verify=get_ssl_verify())
    
    if response.status_code == 200:
        return response.json()
    else:
        console.print(f"[red]Error:[/red] Could not fetch policies. Status code: {response.status_code}")
        return []


def display_policies_table(policies: list):
    """
    Display policies in a rich table format.
    
    Args:
        policies: List of policy objects.
    """
    if not policies:
        console.print("[yellow]No policies found.[/yellow]")
        return
    
    table = Table(
        title=f"Dependency-Track Policies ({len(policies)} total)",
        show_header=True,
        header_style="bold magenta",
        box=box.DOUBLE
    )
    
    table.add_column("Policy Name", style="cyan")
    table.add_column("Violation State", style="yellow")
    table.add_column("Conditions", style="green")
    table.add_column("UUID", style="dim")
    
    for p in policies:
        conditions = p.get("policyConditions", [])
        condition_count = len(conditions) if conditions else 0
        
        table.add_row(
            p.get("name", "N/A"),
            p.get("violationState", "N/A"),
            str(condition_count),
            p.get("uuid", "N/A")
        )
    
    console.print(table)


def generate_violation_summary(violations: list) -> dict:
    """
    Generate a summary of policy violations.
    
    Args:
        violations: List of policy violation objects.
    
    Returns:
        Dictionary containing violation summary statistics.
    """
    summary = {
        "total_violations": len(violations),
        "by_policy": {},
        "by_violation_type": {},
        "by_project": {},
        "by_analysis_state": {},
        "suppressed_count": 0,
        "active_count": 0
    }
    
    for v in violations:
        # Count by policy
        policy_name = v.get("policyCondition", {}).get("policy", {}).get("name", "Unknown")
        summary["by_policy"][policy_name] = summary["by_policy"].get(policy_name, 0) + 1
        
        # Count by violation type
        vtype = v.get("type", "Unknown")
        summary["by_violation_type"][vtype] = summary["by_violation_type"].get(vtype, 0) + 1
        
        # Count by project
        project_name = v.get("component", {}).get("project", {}).get("name", "Unknown")
        summary["by_project"][project_name] = summary["by_project"].get(project_name, 0) + 1
        
        # Count by analysis state
        state = "NOT_SET"
        if v.get("analysis"):
            state = v["analysis"].get("state", "NOT_SET")
        summary["by_analysis_state"][state] = summary["by_analysis_state"].get(state, 0) + 1
        
        # Count suppressed vs active
        if v.get("suppressed", False):
            summary["suppressed_count"] += 1
        else:
            summary["active_count"] += 1
    
    return summary


def display_violation_summary(violations: list):
    """
    Display a summary of policy violations.
    
    Args:
        violations: List of policy violation objects.
    """
    summary = generate_violation_summary(violations)
    
    console.print("\n[bold underline]Policy Violation Summary[/bold underline]\n")
    console.print(f"[white]Total Violations:[/white] {summary['total_violations']}")
    console.print(f"[white]Active:[/white] {summary['active_count']}")
    console.print(f"[white]Suppressed:[/white] {summary['suppressed_count']}")
    
    # By Policy
    if summary["by_policy"]:
        console.print("\n[bold]Violations by Policy:[/bold]")
        policy_table = Table(show_header=True, header_style="bold cyan", box=box.SIMPLE)
        policy_table.add_column("Policy")
        policy_table.add_column("Count", justify="right")
        for policy, count in sorted(summary["by_policy"].items(), key=lambda x: -x[1]):
            policy_table.add_row(policy, str(count))
        console.print(policy_table)
    
    # By Type
    if summary["by_violation_type"]:
        console.print("\n[bold]Violations by Type:[/bold]")
        type_table = Table(show_header=True, header_style="bold yellow", box=box.SIMPLE)
        type_table.add_column("Type")
        type_table.add_column("Count", justify="right")
        for vtype, count in sorted(summary["by_violation_type"].items(), key=lambda x: -x[1]):
            type_table.add_row(vtype, str(count))
        console.print(type_table)
    
    # By Project
    if summary["by_project"]:
        console.print("\n[bold]Violations by Project:[/bold]")
        project_table = Table(show_header=True, header_style="bold green", box=box.SIMPLE)
        project_table.add_column("Project")
        project_table.add_column("Count", justify="right")
        for project, count in sorted(summary["by_project"].items(), key=lambda x: -x[1]):
            project_table.add_row(project, str(count))
        console.print(project_table)
    
    # By Analysis State
    if summary["by_analysis_state"]:
        console.print("\n[bold]Violations by Analysis State:[/bold]")
        state_table = Table(show_header=True, header_style="bold red", box=box.SIMPLE)
        state_table.add_column("State")
        state_table.add_column("Count", justify="right")
        for state, count in sorted(summary["by_analysis_state"].items(), key=lambda x: -x[1]):
            state_table.add_row(state, str(count))
        console.print(state_table)
