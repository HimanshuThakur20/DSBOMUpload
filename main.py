# main.py
import sys
from project import get_or_create_project, get_projects
from bom import upload_bom
from utils.cli_utils import ask_yes_no
from utils.file_utils import file_exists
from rich.console import Console
from rich.table import Table
from packaging import version

console = Console()

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

        table = Table(show_header=True, header_style="bold magenta")
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
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Project Name", style="cyan")
            table.add_column("Version", style="green")
            table.add_column("UUID", style="yellow")
            for project in projects:
                table.add_row(project['name'], project['version'], project['uuid'])
            console.print(table)

            proj_name = input("Enter project name: ")
            proj_version = input("Enter current project version: ")

            bump_version = ask_yes_no("Do you want to upload as a new version?")
            if bump_version:
                try:
                    new_version = str(version.parse(proj_version).next_patch())
                    console.print(f"[cyan]Detected version[/cyan]: {proj_version}, [green]incrementing to[/green]: {new_version}")
                except Exception:
                    console.print("[yellow]Could not parse version. Please enter new version manually.[/yellow]")
                    new_version = input("Enter new version: ")
            else:
                new_version = proj_version

        else:
            proj_name = input("Enter new project name: ")
            proj_version = input("Enter new project version: ")
            new_version = proj_version

        project = get_or_create_project(proj_name, new_version)
        if project is None:
            console.print(f"[red]Error:[/red] A project named '{proj_name}' with version '{new_version}' already exists.")
            console.print("[yellow]Please choose a different version or delete the existing project before retrying.[/yellow]")
            sys.exit(1)
        upload_bom(project["uuid"], bom_file)

        console.print(f"[green]BOM uploaded successfully to project:[/green] {proj_name} (version: {new_version})")

    else:
        console.print(f"[red]Unknown command:[/red] {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
