# main.py
import sys
import os
from project import get_or_create_project, get_projects, get_latest_version
from bom import upload_bom
from sbom_validator import validate_bom_file
from utils.cli_utils import ask_yes_no
from utils.file_utils import file_exists
from rich.console import Console
from rich.table import Table, box
from packaging import version
from validator.depsdev_validator import perform_depsdev_validation


console = Console()


def bump_version(ver_str: str) -> str:
    """Auto-bump a semantic version string."""
    parts = ver_str.split(".")
    if len(parts) == 1:
        return f"{parts[0]}.1"
    elif len(parts) == 2:
        return f"{parts[0]}.{int(parts[1]) + 1}"
    else:
        parts[-1] = str(int(parts[-1]) + 1)
        return ".".join(parts)


def main():
    if len(sys.argv) < 2:
        console.print("[bold yellow]Usage:[/bold yellow] python main.py [command] [options]")
        console.print("[bold]Commands:[/bold]")
        console.print("  [cyan]list-projects[/cyan]                List all projects in Dependency-Track")
        console.print("  [cyan]upload --file <path>[/cyan]         Upload a BOM file")
        console.print("  [cyan]validate --file <path>[/cyan]       Validate a BOM file locally")
        sys.exit(1)

    command = sys.argv[1]

    # =====================================================================================
    # LIST PROJECTS
    # =====================================================================================
    if command == "list-projects":
        projects = get_projects()
        if not projects:
            console.print("[red]No projects found.[/red]")
            sys.exit(0)

        projects = sorted(projects, key=lambda x: x['name'].lower())

        table = Table(show_header=True, header_style="bold magenta", box=box.DOUBLE)
        table.row_styles = ["on #A9A9A9 bold", "on #333333"]
        table.add_column("Project Name", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("UUID", style="yellow")

        for project in projects:
            table.add_row(project['name'], project['version'], project['uuid'])

        console.print(table)
        sys.exit(0)

    # =====================================================================================
    # VALIDATE SBOM (Phase 1 + Phase 2)
    # =====================================================================================
    elif command == "validate":

        if "--file" not in sys.argv:
            console.print("[red]Error:[/red] Missing required argument --file <path>")
            sys.exit(1)

        bom_file = sys.argv[sys.argv.index("--file") + 1]

        if not file_exists(bom_file):
            console.print(f"[red]Error:[/red] File '{bom_file}' does not exist.")
            sys.exit(1)

        console.print(f"[cyan]🔍 Validating BOM file:[/cyan] {bom_file}")

        # =======================================================================
        # PHASE 1 — Local structural detection + type + minimal parsing checks
        # =======================================================================
        result = validate_bom_file(bom_file)

        # -------------------------------
        # Phase 1 – File check
        # -------------------------------
        if not result.file_ok:
            console.print("[red]❌ File validation failed[/red]")
            for err in result.errors:
                console.print(f"  • {err}")
            sys.exit(1)

        # -------------------------------
        # Phase 1 – Parse check
        # -------------------------------
        if not result.parse_ok:
            console.print("[red]❌ Parsing failed[/red]")
            for err in result.errors:
                console.print(f"  • {err}")
            sys.exit(1)

        # -------------------------------
        # Phase 1 – Format + Type display
        # -------------------------------
        console.print(f"[green]✔ Detected Format:[/green] {result.format}")
        console.print(f"[green]✔ Detected SBOM Type:[/green] {result.bom_type}")
        console.print(f"[green]✔ Detected specVersion:[/green] {result.spec_version}")

        # =======================================================================
        # PHASE 2 — Official Schema Validation (CycloneDX / SPDX)
        # =======================================================================
        console.print("\n[cyan]🔍 Running schema validation (Phase 2)...[/cyan]")

        # schema validation results are already inside result.phase2_schema_ok and result.phase2_errors
        schema_ok = result.phase2_schema_ok
        schema_errors = result.phase2_errors

        schema_table = Table(title="Schema Validation", show_header=True, header_style="bold magenta")
        schema_table.add_column("Check")
        schema_table.add_column("Status", justify="center")
        schema_table.add_column("Details", style="dim")

        if schema_ok:
            schema_table.add_row("Schema Validation", "✅ PASS", "BOM structure is valid according to schema")
        else:
            for err in schema_errors:
                schema_table.add_row("Schema Validation", "❌ FAIL", err)

        console.print(schema_table)

        if not schema_ok:
            console.print("[red]❌ Schema validation failed. Fix the BOM and retry.[/red]")
            sys.exit(1)

        # =======================================================================
        # PHASE 3 — deps.dev Validation (Reality Check)
        # =======================================================================
        console.print("\n[cyan]🔍 Running deps.dev package reality check...[/cyan]")

        # Phase 3 requires full parsed JSON/XML
        parsed_bom = None
        try:
            if result.format == "json":
                import json
                parsed_bom = json.load(open(bom_file, "r", encoding="utf-8"))
            else:
                from lxml import etree
                parsed_bom = etree.parse(bom_file)
        except Exception as e:
            console.print(f"[yellow]⚠ Warning: Could not re-parse BOM for deps.dev phase: {e}[/yellow]")

        depsdev_results = perform_depsdev_validation(result.format, parsed_bom)

        deps_table = Table(title="Package Reality Check (deps.dev)", show_header=True, header_style="bold green")
        deps_table.add_column("PURL")
        deps_table.add_column("Status")
        deps_table.add_column("Message", style="dim")

        deps_pass = True
        for purl, ok, msg in depsdev_results:
            if not ok:
                deps_pass = False
            deps_table.add_row(purl, "✅ PASS" if ok else "❌ FAIL", msg)

        console.print(deps_table)

        # =======================================================================
        # FINAL OUTCOME
        # =======================================================================
        if schema_ok and deps_pass:
            console.print("\n[green]✅ Full Validation Passed (Phase 1 + Phase 2 + deps.dev)![/green]")
        else:
            console.print("\n[red]❌ Validation completed with failures. Review errors above.[/red]")

        sys.exit(0)


    # =====================================================================================
    # UPLOAD SBOM
    # =====================================================================================
    elif command == "upload":

        if "--file" not in sys.argv:
            console.print("[red]Error:[/red] Missing argument --file <path>")
            sys.exit(1)

        bom_file = sys.argv[sys.argv.index("--file") + 1]

        if not file_exists(bom_file):
            console.print(f"[red]Error:[/red] The file '{bom_file}' does not exist.")
            sys.exit(1)

        use_existing = ask_yes_no("Do you want to upload to an existing project?")

        if use_existing:
            projects = get_projects()
            projects = sorted(projects, key=lambda x: x['name'].lower())

            table = Table(show_header=True, header_style="bold magenta", box=box.DOUBLE)
            table.add_column("Project Name", style="cyan")
            table.add_column("Version", style="green")
            table.add_column("UUID", style="yellow")

            for project in projects:
                table.add_row(project['name'], project['version'], project['uuid'])

            console.print(table)

            proj_name = input("Enter project name: ").strip()
            latest_version = get_latest_version(proj_name)

            if latest_version:
                new_version = bump_version(latest_version)
                console.print(f"[cyan]Auto-bumping version:[/cyan] {latest_version} → {new_version}")
            else:
                new_version = "1.0"
                console.print(f"[yellow]No version found. Using 1.0[/yellow]")

        else:
            proj_name = input("Enter new project name: ").strip()
            new_version = input("Enter new project version: ").strip()

        project = get_or_create_project(proj_name, new_version)
        if not project:
            console.print(f"[red]❌ Project creation failed.[/red]")
            sys.exit(1)

        upload_bom(project["uuid"], bom_file)

        console.print(f"[green]✅ BOM uploaded successfully![/green]")
        console.print(f"[cyan]Project:[/cyan] {proj_name}  [cyan]Version:[/cyan] {new_version}")
        sys.exit(0)

    else:
        console.print(f"[red]Unknown command:[/red] {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
