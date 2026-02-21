#!/usr/bin/env python3
"""
Script to extract all policy violations from Dependency-Track and export to Excel/CSV.
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


def get_all_policy_violations(suppressed=False):
    """
    Fetch all policy violations from Dependency-Track with pagination.
    """
    url = f"{get_dtrack_url()}api/v1/violation"
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
            
            # Check if we got fewer than page_size, meaning we're done
            if len(violations) < page_size:
                break
            page_number += 1
            print(f"  Fetched page {page_number - 1}, total violations so far: {len(all_violations)}")
        else:
            print(f"Error: Could not fetch policy violations. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return []
    
    return all_violations


def get_all_projects():
    """Fetch all projects to get tags information."""
    url = f"{get_dtrack_url()}api/v1/project"
    response = requests.get(url, headers=get_api_headers(), verify=False)
    
    if response.status_code == 200:
        return response.json()
    return []


def flatten_violation(violation, max_tags=10):
    """
    Flatten a policy violation object for export.
    """
    component = violation.get("component", {})
    policy_condition = violation.get("policyCondition", {})
    policy = policy_condition.get("policy", {})
    project = component.get("project", {})
    
    # Also check for project at violation level
    if not project:
        project = violation.get("project", {})
    
    # Extract tags
    tags_list = project.get("tags", [])
    tag_names = [tag.get("name", "") for tag in tags_list if tag.get("name")]
    
    # Get analysis state
    analysis_state = "NOT_SET"
    if violation.get("analysis"):
        analysis_state = violation["analysis"].get("state", "NOT_SET")
    
    result = {
        "Violation UUID": violation.get("uuid", ""),
        "Violation Type": violation.get("type", ""),
        "Violation State": analysis_state,
        "Suppressed": "Yes" if violation.get("suppressed", False) else "No",
        
        # Policy details
        "Policy Name": policy.get("name", ""),
        "Policy UUID": policy.get("uuid", ""),
        "Policy Violation State": policy.get("violationState", ""),
        
        # Policy condition details
        "Condition UUID": policy_condition.get("uuid", ""),
        "Condition Subject": policy_condition.get("subject", ""),
        "Condition Operator": policy_condition.get("operator", ""),
        "Condition Value": policy_condition.get("value", ""),
        
        # Component details
        "Component UUID": component.get("uuid", ""),
        "Component Name": component.get("name", ""),
        "Component Version": component.get("version", ""),
        "Component Group": component.get("group", ""),
        "Component PURL": component.get("purl", ""),
        "Component CPE": component.get("cpe", ""),
        "Component License": component.get("license", ""),
        
        # Project details
        "Project UUID": project.get("uuid", ""),
        "Project Name": project.get("name", ""),
        "Project Version": project.get("version", ""),
    }
    
    # Add tag columns
    for i in range(max_tags):
        tag_key = f"Tag {i + 1}"
        result[tag_key] = tag_names[i] if i < len(tag_names) else ""
    
    return result


def enrich_violations_with_tags(violations, projects):
    """Add project tags to violations."""
    projects_dict = {p.get("uuid"): p for p in projects if p.get("uuid")}
    
    for violation in violations:
        component = violation.get("component", {})
        project = component.get("project", {})
        
        if not project:
            project = violation.get("project", {})
        
        proj_uuid = project.get("uuid", "")
        
        if proj_uuid and proj_uuid in projects_dict:
            proj_data = projects_dict[proj_uuid]
            tags = proj_data.get("tags", [])
            
            if "project" in component:
                component["project"]["tags"] = tags
            elif "project" in violation:
                violation["project"]["tags"] = tags
    
    return violations


def export_to_csv(violations, filename):
    """Export violations to CSV file."""
    if not violations:
        print("No violations to export.")
        return False
    
    flattened = [flatten_violation(v) for v in violations]
    fieldnames = list(flattened[0].keys())
    
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flattened)
    
    print(f"✓ Exported {len(violations)} violations to CSV: {filename}")
    return True


def export_to_excel(violations, filename):
    """Export violations to Excel file."""
    if not violations:
        print("No violations to export.")
        return False
    
    flattened = [flatten_violation(v) for v in violations]
    
    # Create workbook
    wb = Workbook()
    ws = wb.active
    ws.title = "Policy Violations"
    
    # Get headers
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
    
    # Generate summary
    summary_data = generate_summary(violations)
    
    # Write summary
    summary_ws.cell(row=1, column=1, value="Policy Violations Summary").font = Font(bold=True, size=14)
    summary_ws.cell(row=2, column=1, value=f"Export Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    summary_ws.cell(row=3, column=1, value=f"Total Violations: {summary_data['total']}")
    summary_ws.cell(row=4, column=1, value=f"Active: {summary_data['active']}")
    summary_ws.cell(row=5, column=1, value=f"Suppressed: {summary_data['suppressed']}")
    
    row = 7
    summary_ws.cell(row=row, column=1, value="Violations by Policy:").font = Font(bold=True)
    row += 1
    for policy, count in sorted(summary_data['by_policy'].items(), key=lambda x: -x[1]):
        summary_ws.cell(row=row, column=1, value=policy)
        summary_ws.cell(row=row, column=2, value=count)
        row += 1
    
    row += 1
    summary_ws.cell(row=row, column=1, value="Violations by Project:").font = Font(bold=True)
    row += 1
    for project, count in sorted(summary_data['by_project'].items(), key=lambda x: -x[1]):
        summary_ws.cell(row=row, column=1, value=project)
        summary_ws.cell(row=row, column=2, value=count)
        row += 1
    
    row += 1
    summary_ws.cell(row=row, column=1, value="Violations by Type:").font = Font(bold=True)
    row += 1
    for vtype, count in sorted(summary_data['by_type'].items(), key=lambda x: -x[1]):
        summary_ws.cell(row=row, column=1, value=vtype)
        summary_ws.cell(row=row, column=2, value=count)
        row += 1
    
    # Save
    wb.save(filename)
    print(f"✓ Exported {len(violations)} violations to Excel: {filename}")
    return True


def generate_summary(violations):
    """Generate summary statistics."""
    summary = {
        "total": len(violations),
        "active": 0,
        "suppressed": 0,
        "by_policy": {},
        "by_project": {},
        "by_type": {}
    }
    
    for v in violations:
        # Count suppressed vs active
        if v.get("suppressed", False):
            summary["suppressed"] += 1
        else:
            summary["active"] += 1
        
        # By policy
        policy_name = v.get("policyCondition", {}).get("policy", {}).get("name", "Unknown")
        summary["by_policy"][policy_name] = summary["by_policy"].get(policy_name, 0) + 1
        
        # By project
        component = v.get("component", {})
        project = component.get("project", {})
        if not project:
            project = v.get("project", {})
        project_name = project.get("name", "Unknown")
        summary["by_project"][project_name] = summary["by_project"].get(project_name, 0) + 1
        
        # By type
        vtype = v.get("type", "Unknown")
        summary["by_type"][vtype] = summary["by_type"].get(vtype, 0) + 1
    
    return summary


def main():
    """Main function."""
    print("=" * 60)
    print("Dependency-Track Policy Violations Export Tool")
    print("=" * 60)
    
    # Test connection first
    print("\nTesting connection to Dependency-Track...")
    try:
        url = f"{get_dtrack_url()}api/v1/project"
        response = requests.get(url, headers=get_api_headers(), verify=False)
        if response.status_code == 200:
            print(f"✓ Connected successfully. Found {len(response.json())} projects.")
        else:
            print(f"✗ Connection failed. Status code: {response.status_code}")
            sys.exit(1)
    except Exception as e:
        print(f"✗ Connection error: {e}")
        sys.exit(1)
    
    # Fetch all projects for tags
    print("\nFetching projects for tag information...")
    projects = get_all_projects()
    print(f"  Found {len(projects)} projects")
    
    # Fetch all policy violations
    print("\nFetching policy violations...")
    violations = get_all_policy_violations(suppressed=False)
    
    if not violations:
        print("No policy violations found.")
        sys.exit(0)
    
    print(f"\n✓ Found {len(violations)} policy violations")
    
    # Enrich with tags
    print("\nEnriching violations with project tags...")
    violations = enrich_violations_with_tags(violations, projects)
    
    # Generate filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_filename = f"policy_violations_{timestamp}.csv"
    excel_filename = f"policy_violations_{timestamp}.xlsx"
    
    # Export to both formats
    print("\nExporting to CSV...")
    export_to_csv(violations, csv_filename)
    
    print("\nExporting to Excel...")
    export_to_excel(violations, excel_filename)
    
    # Print summary
    summary = generate_summary(violations)
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total Violations: {summary['total']}")
    print(f"Active: {summary['active']}")
    print(f"Suppressed: {summary['suppressed']}")
    
    print("\nViolations by Policy:")
    for policy, count in sorted(summary['by_policy'].items(), key=lambda x: -x[1]):
        print(f"  • {policy}: {count}")
    
    print("\nViolations by Type:")
    for vtype, count in sorted(summary['by_type'].items(), key=lambda x: -x[1]):
        print(f"  • {vtype}: {count}")
    
    print("\n" + "=" * 60)
    print("Export completed successfully!")
    print(f"  CSV:   {csv_filename}")
    print(f"  Excel: {excel_filename}")
    print("=" * 60)


if __name__ == "__main__":
    main()
