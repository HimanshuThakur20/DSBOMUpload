# SBOM Upload - Dependency-Track CLI Tool

A command-line tool for managing Software Bill of Materials (SBOM) uploads to [Dependency-Track](https://dependencytrack.org/).

## Features

- **List Projects** - View all projects in Dependency-Track
- **Upload BOM** - Upload CycloneDX BOM files to existing or new projects
- **Export Projects** - Export all projects with tags to CSV format
- **Auto Version Bumping** - Automatically increment version numbers when uploading

## Prerequisites

- Python 3.11 or higher
- Access to a Dependency-Track server
- Dependency-Track API key

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/HimanshuThakur20/DSBOMUpload.git
   cd DSBOMUpload
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # Linux/Mac
   source .venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Set the following environment variables:

| Variable | Description | Required |
|----------|-------------|----------|
| `DTRACK_URL` | Dependency-Track server URL | Yes |
| `DTRACK_API_KEY` | API key for authentication | Yes |
| `DTRACK_SSL_VERIFY` | SSL verification (`true`/`false`) | No (default: `false`) |

### Example (PowerShell)
```powershell
$env:DTRACK_URL = "https://your-dependency-track-server.com/"
$env:DTRACK_API_KEY = "your-api-key-here"
$env:DTRACK_SSL_VERIFY = "false"
```

### Example (Bash)
```bash
export DTRACK_URL="https://your-dependency-track-server.com/"
export DTRACK_API_KEY="your-api-key-here"
export DTRACK_SSL_VERIFY="false"
```

## Usage

### List All Projects
```bash
python main.py list-projects
```
Displays all projects in Dependency-Track in a formatted table.

### Upload a BOM File
```bash
python main.py upload --file <path-to-bom-file>
```
Options:
- Upload to an existing project (auto-bumps version)
- Create a new project with custom name and version

### Export Projects to CSV
```bash
python main.py export-projects [options]
```
Options:
- `--output <path>` - Output file path (default: `projects.csv`)
- `--latest-only` - Export only the latest version of each project
- `--max-tags <n>` - Maximum number of tag columns (default: 10)

Example:
```bash
python main.py export-projects --output applications_export.csv --latest-only --max-tags 5
```

## Project Structure

```
SBOMUPLOAD/
├── main.py              # CLI entry point
├── config.py            # Configuration and environment variables
├── project.py           # Project management functions
├── bom.py               # BOM upload functionality
├── requirements.txt     # Python dependencies
├── schemas/
│   └── json/
│       └── bom-1.6.schema.json  # CycloneDX schema
├── utils/
│   ├── cli_utils.py     # CLI helper functions
│   └── file_utils.py    # File handling utilities
└── validator/           # Validation modules
```

## Dependencies

- `requests` - HTTP client for API communication
- `rich` - Beautiful terminal output formatting
- `packaging` - Version parsing and comparison

## License

This project is for internal use.

## Contributing

1. Create a feature branch from `main`
2. Make your changes
3. Submit a pull request

## Support

For issues or questions, please create an issue in the repository.
