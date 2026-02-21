# main.py
import sys
from project import get_or_create_project, get_projects, get_latest_version
from bom import upload_bom
from bulk_upload import bulk_upload_host, preview_host_parsing
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
        console.print("  [cyan]bulk-upload-host[/cyan]             Bulk upload Host category SBOMs")
        console.print("      --folder <path>              Folder containing Host SBOMs (with subfolders)")
        console.print("      --tags <excel_path>          Excel file with account number to tags mapping")
        console.print("      [--version <ver>]            Project version (default: 1.0)")
        console.print("      [--dry-run]                  Simulate upload without actually uploading")
        console.print("  [cyan]preview-host[/cyan]                 Preview Host SBOM parsing")
        console.print("      --folder <path>              Folder containing Host SBOMs")
        console.print("      --tags <excel_path>          Excel file with tags")
        console.print("      [--limit <n>]                Number of files to preview (default: 10)")
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

    elif command == "bulk-upload-host":
        # Parse arguments for bulk upload
        if "--folder" not in sys.argv or "--tags" not in sys.argv:
            console.print("[red]Error:[/red] You must provide both --folder and --tags arguments")
            console.print("Usage: python main.py bulk-upload-host --folder <path> --tags <excel_path> [--version <ver>] [--dry-run]")
            sys.exit(1)
        
        folder_index = sys.argv.index("--folder") + 1
        tags_index = sys.argv.index("--tags") + 1
        
        sbom_folder = sys.argv[folder_index]
        tags_excel = sys.argv[tags_index]
        
        # Optional version argument
        proj_version = "1.0"
        if "--version" in sys.argv:
            version_index = sys.argv.index("--version") + 1
            proj_version = sys.argv[version_index]
        
        # Optional dry-run flag
        dry_run = "--dry-run" in sys.argv
        
        # Optional limit argument
        limit = 0
        if "--limit" in sys.argv:
            limit_index = sys.argv.index("--limit") + 1
            limit = int(sys.argv[limit_index])
        
        if dry_run:
            console.print("[yellow]DRY RUN MODE - No actual uploads will be performed[/yellow]")
        
        bulk_upload_host(sbom_folder, tags_excel, version=proj_version, dry_run=dry_run, limit=limit)

    elif command == "preview-host":
        # Parse arguments for preview
        if "--folder" not in sys.argv or "--tags" not in sys.argv:
            console.print("[red]Error:[/red] You must provide both --folder and --tags arguments")
            console.print("Usage: python main.py preview-host --folder <path> --tags <excel_path> [--limit <n>]")
            sys.exit(1)
        
        folder_index = sys.argv.index("--folder") + 1
        tags_index = sys.argv.index("--tags") + 1
        
        sbom_folder = sys.argv[folder_index]
        tags_excel = sys.argv[tags_index]
        
        # Optional limit argument
        limit = 10
        if "--limit" in sys.argv:
            limit_index = sys.argv.index("--limit") + 1
            limit = int(sys.argv[limit_index])
        
        preview_host_parsing(sbom_folder, tags_excel, limit=limit)

    else:
        console.print(f"[red]Unknown command:[/red] {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
