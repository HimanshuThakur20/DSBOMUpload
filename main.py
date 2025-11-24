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
from validator.policy_enforcer import PolicyEnforcer
from rich.table import Table
from rich.console import Console

console = Console()


def bump_version(ver_str: str) -> str:
    parts = ver_str.split(".")
    if len(parts) == 1:
        return f"{parts[0]}.1"
    elif len(parts) == 2:
        return f"{parts[0]}.{int(parts[1]) + 1}"
    else:
        parts[-1] = str(int(parts[-1]) + 1)
        return ".".join(parts)


def _print_phase_header(title: str):
    console.print("\n" + ("=" * 72))
    console.print(f"[bold cyan]{title}[/bold cyan]")
    console.print(("=" * 72) + "\n")


def main():
    if len(sys.argv) < 2:
        console.print("[bold yellow]Usage:[/bold yellow] python main.py [command] [options]")
        console.print("[bold]Commands:[/bold]")
        console.print("  [cyan]list-projects[/cyan]                List all projects in Dependency-Track")
        console.print("  [cyan]upload --file <path>[/cyan]         Upload a BOM file")
        console.print("  [cyan]validate --file <path>[/cyan]       Validate a BOM file locally")
        sys.exit(1)

    command = sys.argv[1]

    # -------------------------
    # list-projects
    # -------------------------
    if command == "list-projects":
        projects = get_projects()
        projects = projects or []
        projects = sorted(projects, key=lambda x: x['name'].lower()) if projects else []
        if not projects:
            console.print("[red]No projects found.[/red]")
            sys.exit(0)

        table = Table(show_header=True, header_style="bold magenta", box=box.DOUBLE)
        table.add_column("Project Name", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("UUID", style="yellow")
        for p in projects:
            table.add_row(p['name'], p['version'], p['uuid'])
        console.print(table)
        sys.exit(0)

    # -------------------------
    # validate
    # -------------------------
    elif command == "validate":
        if "--file" not in sys.argv:
            console.print("[red]Error:[/red] Missing required argument --file <path>")
            sys.exit(1)

        bom_file = sys.argv[sys.argv.index("--file") + 1]
        if not file_exists(bom_file):
            console.print(f"[red]Error:[/red] File '{bom_file}' not found.")
            sys.exit(1)

        console.print(f"[bold]Validating BOM:[/bold] {bom_file}")

        # PHASE 1
        _print_phase_header("PHASE 1 — File / Parsing / SBOM Detection")
        res = validate_bom_file(bom_file)

        if not res.file_ok:
            console.print("[red]❌ File checks failed[/red]")
            for e in res.errors:
                console.print(f"  • {e}")
            sys.exit(1)

        if not res.parse_ok:
            console.print("[red]❌ Parsing failed[/red]")
            for e in res.errors:
                console.print(f"  • {e}")
            sys.exit(1)

        console.print(f"[green]✔ Format:[/green] {res.format}")
        console.print(f"[green]✔ SBOM Type:[/green] {res.bom_type}")
        console.print(f"[green]✔ specVersion:[/green] {res.spec_version}")

        # PHASE 2 - Schema validation
        _print_phase_header("PHASE 2 — Schema Validation (dynamic)")
        # results already populated by sbom_validator (phase2 fields)
        if res.phase2_schema_ok:
            console.print("[green]✅ Schema validation passed.[/green]")
        else:
            console.print("[red]❌ Schema validation failed.[/red]")
            for err in res.phase2_schema_errors:
                console.print(f"  • {err}")
            sys.exit(1)

        # PHASE 3 - semantic + policy
        _print_phase_header("PHASE 3 — Semantic checks & Policy enforcement")

        enforcer = PolicyEnforcer()
        policy_ok, policy_results = enforcer.enforce(
            detection_result=res,
            parsed_bom=res.parsed
        )

        # -----------------------------------------
        # COLOR helper
        # -----------------------------------------
        def colorize(status: str):
            if status == "PASS":
                return "[green]PASS[/green]"
            if status == "WARN":
                return "[yellow]WARN[/yellow]"
            if status == "FAIL":
                return "[red]FAIL[/red]"
            return status


        # -----------------------------------------
        # CI Minimal table (ALWAYS FIRST)
        # -----------------------------------------
        ci_table = Table(
            title="Policy Results (CI Minimal)",
            show_header=True,
            header_style="bold white"
        )
        ci_table.add_column("Rule")
        ci_table.add_column("Severity")
        ci_table.add_column("Status")
        ci_table.add_column("Message", style="dim")

        for pr in policy_results:
            ci_table.add_row(
                pr.rule,
                pr.severity,
                colorize(pr.status),
                pr.message
            )

        console.print(ci_table)

        if not policy_ok:
            console.print("[red]Policy checks failed.[/red]")
        else:
            console.print("[green]Policy checks passed.[/green]")


        # -----------------------------------------
        # Detailed block (ALWAYS SECOND)
        # -----------------------------------------
        console.print("\n[bold underline]Detailed Policy Breakdown[/bold underline]\n")

        for pr in policy_results:
            console.print(f"[white]Rule:[/white] {pr.rule}")
            console.print(f"[white]ID:[/white] {pr.id}")
            console.print(f"[white]Category:[/white] {pr.category}")
            console.print(f"[white]Severity:[/white] {pr.severity}")
            console.print(f"[white]Status:[/white] {colorize(pr.status)}")
            console.print(f"[white]Description:[/white] {pr.description}")
            console.print(f"[white]Reason:[/white] {pr.reason}")
            console.print(f"[white]Message:[/white] {pr.message}")

            if pr.details:
                console.print(f"[white]Details:[/white] {pr.details}")

            console.print("-" * 80)


        # PHASE 4 - deps.dev package verification (Option A: ALWAYS run)
        _print_phase_header("PHASE 4 — deps.dev package reality check (always ON)")
        try:
            deps_results = perform_depsdev_validation(res.format, res.parsed)
        except Exception as e:
            console.print(f"[yellow]⚠ deps.dev validation failed to run: {e}[/yellow]")
            deps_results = []

        deps_table = Table(title="deps.dev Results", show_header=True, header_style="bold magenta")
        deps_table.add_column("PURL/Identifier")
        deps_table.add_column("Status")
        deps_table.add_column("Message", style="dim")

        overall_deps_ok = True
        for purl, ok, msg in deps_results:
            status = "PASS" if ok else "FAIL"
            if not ok:
                overall_deps_ok = False
            deps_table.add_row(purl, status, msg)
        console.print(deps_table)

        # Final decision
        if res.phase2_schema_ok and policy_ok and overall_deps_ok:
            console.print("\n[bold green]✅ All validation phases passed. SBOM is valid.[/bold green]")
            sys.exit(0)
        else:
            console.print("\n[bold red]❌ Validation completed with failures.[/bold red]")
            if not res.phase2_schema_ok:
                console.print(" - Schema validation failed.")
            if not policy_ok:
                console.print(" - Policy checks failed.")
            if not overall_deps_ok:
                console.print(" - deps.dev package reality check failed.")
            sys.exit(2)

    # -------------------------
    # upload
    # -------------------------
    elif command == "upload":
        if "--file" not in sys.argv:
            console.print("[red]Error:[/red] Missing required argument --file <path>")
            sys.exit(1)

        bom_file = sys.argv[sys.argv.index("--file") + 1]
        if not file_exists(bom_file):
            console.print(f"[red]Error:[/red] File '{bom_file}' not found.")
            sys.exit(1)

        use_existing = ask_yes_no("Do you want to upload to an existing project?")
        if use_existing:
            projects = get_projects() or []
            projects = sorted(projects, key=lambda x: x['name'].lower())
            table = Table(show_header=True, header_style="bold magenta", box=box.DOUBLE)
            table.add_column("Project Name", style="cyan")
            table.add_column("Version", style="green")
            table.add_column("UUID", style="yellow")
            for p in projects:
                table.add_row(p['name'], p['version'], p['uuid'])
            console.print(table)
            proj_name = input("Enter project name: ").strip()
            latest_version = get_latest_version(proj_name)
            if latest_version:
                new_version = bump_version(latest_version)
                console.print(f"[cyan]Auto-bumping version:[/cyan] {latest_version} → {new_version}")
            else:
                new_version = "1.0"
                console.print("[yellow]No existing version found; using 1.0[/yellow]")
        else:
            proj_name = input("Enter new project name: ").strip()
            new_version = input("Enter new project version: ").strip()

        project = get_or_create_project(proj_name, new_version)
        if not project:
            console.print("[red]❌ Project create / retrieve failed.[/red]")
            sys.exit(1)
        upload_bom(project["uuid"], bom_file)
        console.print("[green]✅ BOM uploaded successfully.[/green]")
        console.print(f"[cyan]Project:[/cyan] {proj_name} [cyan]Version:[/cyan] {new_version}")
        sys.exit(0)

    else:
        console.print(f"[red]Unknown command:[/red] {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
