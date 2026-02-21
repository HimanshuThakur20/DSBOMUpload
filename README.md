# DSBOMUpload

A CLI tool for uploading Software Bill of Materials (SBOM) files to Dependency-Track, with support for bulk uploads and automatic tag mapping.

## Features

- **Single SBOM Upload** - Upload individual SBOM files to new or existing projects
- **Bulk Upload** - Upload thousands of Host SBOMs with automatic project naming and tagging
- **Auto Version Bumping** - Automatically increments version numbers when uploading to existing projects
- **Dry Run Mode** - Simulate bulk uploads without making actual API calls
- **Preview Mode** - Preview how filenames will be parsed before uploading
- **Excel-based Tag Mapping** - Map account numbers to tags using Excel files

## Prerequisites

- Python 3.10+
- Dependency-Track instance with API access

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/HimanshuThakur20/DSBOMUpload.git
   cd DSBOMUpload
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   .venv\Scripts\Activate.ps1  # Windows PowerShell
   # or
   source .venv/bin/activate   # Linux/macOS
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Set the following environment variables:

```bash
# Windows PowerShell
$env:DTRACK_URL = "https://your-dependency-track-instance.com"
$env:DTRACK_API_KEY = "your-api-key"

# Linux/macOS
export DTRACK_URL="https://your-dependency-track-instance.com"
export DTRACK_API_KEY="your-api-key"
```

## Usage

### List Projects

List all projects in Dependency-Track:

```bash
python main.py list-projects
```

### Upload Single SBOM

Upload a single BOM file:

```bash
python main.py upload --file path/to/sbom.json
```

The CLI will prompt you to select an existing project or create a new one.

### Bulk Upload Host SBOMs

Upload multiple Host SBOMs with automatic project naming and tagging:

```bash
python main.py bulk-upload-host --folder "Host/Part_1" --tags "Account data.xlsx" [--version 1.0] [--dry-run] [--limit 100]
```

**Arguments:**
- `--folder` - Folder containing Host SBOM JSON files (scans recursively)
- `--tags` - Excel file mapping account numbers to tags
- `--version` - Project version (default: 1.0)
- `--dry-run` - Simulate upload without making API calls
- `--limit` - Limit number of files to process (0 = no limit)

**Filename Format:**
Host SBOMs should follow this naming convention:
```
<account_number>_<ip>_<hash>_<timestamp>.json
```
Example: `22206351557_ip-10-53-64-89_4df91bb73d15db3b_2026-02-17T08-16-56Z.json`

**Project Naming:**
Projects are automatically named as: `<account_number>_Host_<ip>`
Example: `22206351557_Host_ip-10-53-64-89`

### Preview Host Parsing

Preview how filenames will be parsed without uploading:

```bash
python main.py preview-host --folder "Host/Part_1" --tags "Account data.xlsx" [--limit 20]
```

## Excel Tags File Format

The tags Excel file should have:
- **Column A**: Account Number
- **Remaining columns**: Tags to apply

| AccountNumber | Tag1 | Tag2 | Tag3 |
|---------------|------|------|------|
| 22206351557 | prod | aws | critical |
| 102809085638 | dev | azure | |

## Project Structure

```
DSBOMUpload/
├── main.py              # CLI entry point
├── config.py            # Configuration (environment variables)
├── project.py           # Project management (create/list projects)
├── bom.py               # BOM upload functionality
├── bulk_upload.py       # Bulk upload with tag mapping
├── requirements.txt     # Python dependencies
├── utils/
│   ├── cli_utils.py     # CLI helper functions
│   └── file_utils.py    # File utility functions
└── schemas/
    └── json/            # JSON schemas for validation
```

## License

MIT
