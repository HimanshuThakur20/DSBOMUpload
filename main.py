# main.py
import sys
from project import get_or_create_project, get_projects, get_latest_version
from bom import upload_bom
from utils.cli_utils import ask_yes_no
from utils.file_utils import file_exists
from rich.console import Console
from rich.table import Table, box
from packaging import version

console = Console()

def auto_bump_version(ver: str) -> str:
    """Auto bump patch version."""
    parts = ver.split(".")
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
        sys.exit(1)

    command = sys.argv[1]

    if command == "list-projects":
        projects = get_projects()
        if not projects:
            console.print("[red]No projects found.[/red]")
            sys.exit(0)

        # Sort alphabetically by project name
        projects = sorted(projects, key=lambda x: x['name'].lower())

        table = Table(show_header=True, header_style="bold magenta", box=box.DOUBLE)
        table.row_styles = ["on #A9A9A9 bold", "on #333333"]
        table.add_column("Project Name", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("UUID", style="yellow")

        for project in projects:
            table.add_row(project['name'], project['version'], project['uuid'])

        console.print(table)

    elif command == "upload":
        if "--file" not in sys.argv:
            console.print("[red]Error:[/red] You must provide a BOM file using [yellow]--file <path>[/yellow]")
            sys.exit(1)

        file_index = sys.argv.index("--file") + 1
        bom_file = sys.argv[file_index]

        if not file_exists(bom_file):
            console.print(f"[red]Error:[/red] The file '{bom_file}' does not exist.")
            sys.exit(1)

        use_existing = ask_yes_no("Do you want to upload to an existing project?")
        if use_existing:
            projects = get_projects()
            if not projects:
                console.print("[red]No existing projects found in Dependency-Track.[/red]")
                sys.exit(0)

            # Sort alphabetically before displaying
            projects = sorted(projects, key=lambda x: x['name'].lower())

            table = Table(show_header=True, header_style="bold magenta", box=box.DOUBLE)
            table.row_styles = ["on #A9A9A9 bold", "on #333333"]
            table.add_column("Project Name", style="cyan")
            table.add_column("Version", style="green")
            table.add_column("UUID", style="yellow")

            for project in projects:
                table.add_row(project['name'], project['version'], project['uuid'])
            console.print(table)

            proj_name = input("Enter project name: ").strip()
            latest_version = get_latest_version(proj_name)

            if latest_version:
                new_version = auto_bump_version(latest_version)
                console.print(f"[cyan]Auto-bumping version:[/cyan] {latest_version} → {new_version}")
            else:
                new_version = "1.0"
                console.print(f"[yellow]No previous version found, starting with {new_version}[/yellow]")

        else:
            proj_name = input("Enter new project name: ")
            new_version = input("Enter new project version: ")

        project = get_or_create_project(proj_name, new_version)
        upload_bom(project["uuid"], bom_file)

        console.print(f"[green]✅ BOM uploaded successfully![/green] → [cyan]{proj_name}[/cyan] (version: [bold]{new_version}[/bold])")

    else:
        console.print(f"[red]Unknown command:[/red] {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
