#!/usr/bin/env python3
"""
Script to extract policy violations for specific projects from Dependency-Track.
"""

import sys
import csv
from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
import requests
import urllib3
from config import get_api_headers, get_dtrack_url

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Target projects to extract
TARGET_PROJECTS = [
    "AMS",
    "AU ACE",
    "Drishti",
    "ERPNext",
    "Elision IVR",
    "Gyftr",
    "KMT",
    "Nanobanking",
    "Niyantran"
]


def get_all_projects():
    """Fetch all projects."""
    url = f"{get_dtrack_url()}api/v1/project"
    response = requests.get(url, headers=get_api_headers(), verify=False)
    
    if response.status_code == 200:
        return response.json()
    return []


def get_project_violations(project_uuid, suppressed=False):
    """Fetch policy violations for a specific project."""
    url = f"{get_dtrack_url()}api/v1/violation/project/{project_uuid}"
    params = {"suppressed": str(suppressed).lower()}
    
    all_violations = []
    page_number = 1
    page_size = 100
    
    while True:
        params["pageNumber"] = page_number
        params["pageSize"] = page_size
        
        response = requests.get(url, headers=get_api_headers(), params=params, verify=False)
        
        if response.status_code == 200:
            violations = response.json()
            if not violations:
                break
            all_violations.extend(violations)
            
            if len(violations) < page_size:
                break
            page_number += 1
        else:
            print(f"  Error fetching violations: {response.status_code}")
            return []
    
    return all_violations


def project_matches_target(project_name, targets):
    """Check if project name matches any target (case-insensitive, partial match)."""
    project_lower = project_name.lower()
    for target in targets:
        target_lower = target.lower()
        # Check if target is contained in project name or vice versa
        if target_lower in project_lower or project_lower.startswith(target_lower):
            return True
    return False


def flatten_violation(violation, max_tags=10):
    """Flatten a policy violation object for export."""
    component = violation.get("component", {})
    policy_condition = violation.get("policyCondition", {})
    policy = policy_condition.get("policy", {})
    project = component.get("project", {})
    
    if not project:
        project = violation.get("project", {})
    
    tags_list = project.get("tags", [])
    tag_names = [tag.get("name", "") for tag in tags_list if tag.get("name")]
    
    analysis_state = "NOT_SET"
    if violation.get("analysis"):
        analysis_state = violation["analysis"].get("state", "NOT_SET")
    
    result = {
        "Violation UUID": violation.get("uuid", ""),
        "Violation Type": violation.get("type", ""),
        "Violation State": analysis_state,
        "Suppressed": "Yes" if violation.get("suppressed", False) else "No",
        "Policy Name": policy.get("name", ""),
        "Policy UUID": policy.get("uuid", ""),
        "Policy Violation State": policy.get("violationState", ""),
        "Condition UUID": policy_condition.get("uuid", ""),
        "Condition Subject": policy_condition.get("subject", ""),
        "Condition Operator": policy_condition.get("operator", ""),
        "Condition Value": policy_condition.get("value", ""),
        "Component UUID": component.get("uuid", ""),
        "Component Name": component.get("name", ""),
        "Component Version": component.get("version", ""),
        "Component Group": component.get("group", ""),
        "Component PURL": component.get("purl", ""),
        "Component CPE": component.get("cpe", ""),
        "Component License": component.get("license", ""),
        "Project UUID": project.get("uuid", ""),
        "Project Name": project.get("name", ""),
        "Project Version": project.get("version", ""),
    }
    
    for i in range(max_tags):
        tag_key = f"Tag {i + 1}"
        result[tag_key] = tag_names[i] if i < len(tag_names) else ""
    
    return result


def export_to_excel(violations, filename, matched_projects):
    """Export violations to Excel file."""
    if not violations:
        print("No violations to export.")
        return False
    
    flattened = [flatten_violation(v) for v in violations]
    
    wb = Workbook()
    ws = wb.active
    ws.title = "Policy Violations"
    
    headers = list(flattened[0].keys())
    
    # Write headers
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill(start_color="C00000", end_color="C00000", fill_type="solid")
        cell.alignment = Alignment(horizontal="center")
    
    # Write data
    for row, record in enumerate(flattened, 2):
        for col, header in enumerate(headers, 1):
            ws.cell(row=row, column=col, value=record.get(header, ""))
    
    # Auto-adjust column widths
    for column in ws.columns:
        max_length = 0
        column_letter = get_column_letter(column[0].column)
        
        for cell in column:
            try:
                if len(str(cell.value)) > max_length:
                    max_length = len(str(cell.value))
            except:
                pass
        
        adjusted_width = min(max_length + 2, 50)
        ws.column_dimensions[column_letter].width = adjusted_width
    
    # Add borders
    thin_border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    for row in ws.iter_rows(min_row=1, max_row=len(flattened) + 1):
        for cell in row:
            cell.border = thin_border
    
    # Add summary sheet
    summary_ws = wb.create_sheet("Summary")
    
    summary_ws.cell(row=1, column=1, value="Policy Violations - Selected Projects").font = Font(bold=True, size=14)
    summary_ws.cell(row=2, column=1, value=f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    summary_ws.cell(row=3, column=1, value=f"Total Violations: {len(violations)}")
    
    row = 5
    summary_ws.cell(row=row, column=1, value="Projects Included:").font = Font(bold=True)
    row += 1
    
    # Count violations per project
    project_counts = {}
    for v in violations:
        component = v.get("component", {})
        project = component.get("project", {})
        if not project:
            project = v.get("project", {})
        proj_name = project.get("name", "Unknown")
        proj_version = project.get("version", "")
        key = f"{proj_name} (v{proj_version})" if proj_version else proj_name
        project_counts[key] = project_counts.get(key, 0) + 1
    
    for proj, count in sorted(project_counts.items(), key=lambda x: -x[1]):
        summary_ws.cell(row=row, column=1, value=proj)
        summary_ws.cell(row=row, column=2, value=count)
        row += 1
    
    row += 1
    summary_ws.cell(row=row, column=1, value="Violations by Policy:").font = Font(bold=True)
    row += 1
    
    policy_counts = {}
    for v in violations:
        policy_name = v.get("policyCondition", {}).get("policy", {}).get("name", "Unknown")
        policy_counts[policy_name] = policy_counts.get(policy_name, 0) + 1
    
    for policy, count in sorted(policy_counts.items(), key=lambda x: -x[1]):
        summary_ws.cell(row=row, column=1, value=policy)
        summary_ws.cell(row=row, column=2, value=count)
        row += 1
    
    wb.save(filename)
    print(f"✓ Exported {len(violations)} violations to: {filename}")
    return True


def main():
    print("=" * 60)
    print("Policy Violations Export - Selected Projects")
    print("=" * 60)
    print("\nTarget Projects:")
    for p in TARGET_PROJECTS:
        print(f"  • {p}")
    
    # Get all projects
    print("\nFetching all projects...")
    all_projects = get_all_projects()
    print(f"  Found {len(all_projects)} total projects")
    
    # Find matching projects
    matched_projects = []
    for proj in all_projects:
        proj_name = proj.get("name", "")
        if project_matches_target(proj_name, TARGET_PROJECTS):
            matched_projects.append(proj)
    
    print(f"\nMatched {len(matched_projects)} projects:")
    for proj in matched_projects:
        print(f"  • {proj.get('name')} (v{proj.get('version', 'N/A')})")
    
    if not matched_projects:
        print("\nNo matching projects found!")
        sys.exit(1)
    
    # Fetch violations for each matched project
    all_violations = []
    print("\nFetching violations for each project...")
    
    for idx, proj in enumerate(matched_projects, 1):
        proj_name = proj.get("name", "Unknown")
        proj_uuid = proj.get("uuid")
        proj_version = proj.get("version", "N/A")
        
        print(f"  [{idx}/{len(matched_projects)}] {proj_name} v{proj_version}...", end=" ")
        
        violations = get_project_violations(proj_uuid)
        
        # Enrich violations with project tags
        for v in violations:
            component = v.get("component", {})
            if "project" in component:
                component["project"]["tags"] = proj.get("tags", [])
            elif "project" in v:
                v["project"]["tags"] = proj.get("tags", [])
        
        all_violations.extend(violations)
        print(f"{len(violations)} violations")
    
    print(f"\n✓ Total violations found: {len(all_violations)}")
    
    if not all_violations:
        print("No violations found for the selected projects.")
        sys.exit(0)
    
    # Export to Excel
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"policy_violations_selected_projects_{timestamp}.xlsx"
    
    print(f"\nExporting to Excel...")
    export_to_excel(all_violations, filename, matched_projects)
    
    # Print summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    policy_counts = {}
    project_counts = {}
    
    for v in all_violations:
        policy_name = v.get("policyCondition", {}).get("policy", {}).get("name", "Unknown")
        policy_counts[policy_name] = policy_counts.get(policy_name, 0) + 1
        
        component = v.get("component", {})
        project = component.get("project", {})
        if not project:
            project = v.get("project", {})
        proj_name = project.get("name", "Unknown")
        project_counts[proj_name] = project_counts.get(proj_name, 0) + 1
    
    print("\nViolations by Project:")
    for proj, count in sorted(project_counts.items(), key=lambda x: -x[1]):
        print(f"  • {proj}: {count}")
    
    print("\nViolations by Policy:")
    for policy, count in sorted(policy_counts.items(), key=lambda x: -x[1]):
        print(f"  • {policy}: {count}")
    
    print("\n" + "=" * 60)
    print(f"Export completed: {filename}")
    print("=" * 60)


if __name__ == "__main__":
    main()
