# DSBOMUpload

A comprehensive CLI tool for managing Software Bill of Materials (SBOM) in Dependency-Track, with support for bulk uploads, project exports, policy violation extraction, and automatic tag mapping.

## Features

- **Single SBOM Upload** - Upload individual SBOM files to new or existing projects
- **Bulk Upload** - Upload thousands of Host SBOMs with automatic project naming and tagging
- **Auto Version Bumping** - Automatically increments version numbers when uploading to existing projects
- **Dry Run Mode** - Simulate bulk uploads without making actual API calls
- **Preview Mode** - Preview how filenames will be parsed before uploading
- **Excel-based Tag Mapping** - Map account numbers to tags using Excel files
- **Project Export to Excel** - Export all projects with detailed metrics and vulnerabilities
- **Policy Violations Export** - Extract all policy violations to Excel/CSV with detailed information
- **Project Management** - List, create, and delete projects

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

### Windows PowerShell
```powershell
$env:DTRACK_URL = "https://your-dependency-track-instance.com"
$env:DTRACK_API_KEY = "your-api-key"
```

### Linux/macOS
```bash
export DTRACK_URL="https://your-dependency-track-instance.com"
export DTRACK_API_KEY="your-api-key"
```

---

## Commands Reference

### 1. List Projects

List all projects in Dependency-Track in a formatted table.

```bash
python main.py list-projects
```

**Output:** Displays project name, version, and UUID in a table format.

---

### 2. Export Projects to Excel

Export all projects with detailed metrics (vulnerabilities, risk scores, components) to an Excel file.

#### Via main.py command:
```bash
python main.py export-projects-excel
```

#### Via standalone script:
```bash
python simple_export_projects.py
```

#### Via standalone script (with rich console output):
```bash
python export_projects_to_excel.py
```

**Output:** Creates `dependency_track_projects_<timestamp>.xlsx` with:
- Project Name, Version, UUID, Active status, Classifier
- Created Date, Last BOM Import, Last BOM Import Format
- Tags
- Total Components, Vulnerable Components
- Critical/High/Medium/Low/Info/Unassigned Vulnerabilities
- Total Vulnerabilities, Policy Violations
- Risk Scores (License, Operational, Technical, Business, Inherited)

---

### 3. Validate SBOM File

Validate a BOM file locally without uploading. Performs multi-phase validation including file checks, parsing, SBOM type detection, schema validation, semantic checks, and policy enforcement.

```bash
python main.py validate --file <path_to_sbom>
```

**Examples:**
```bash
# Validate a JSON SBOM
python main.py validate --file sbom.json

# Validate an XML SBOM
python main.py validate --file bom.xml

# Validate CycloneDX SBOM
python main.py validate --file cyclonedx-bom.json

# Validate SPDX SBOM
python main.py validate --file spdx-sbom.json
```

**Validation Phases:**

| Phase | Description |
|-------|-------------|
| **Phase 1** | File existence, format detection (.json/.xml), parsing, SBOM type detection (CycloneDX/SPDX) |
| **Phase 2** | Schema validation against CycloneDX or SPDX schemas (auto-downloads schemas if needed) |
| **Phase 3** | Semantic checks and policy enforcement |

**Supported Formats:**
- CycloneDX JSON (1.4, 1.5, 1.6)
- CycloneDX XML (1.4, 1.5, 1.6)
- SPDX JSON (2.2, 2.3)
- SPDX XML

**Output:** Detailed validation report showing:
- File and parsing status
- Detected format and SBOM type
- Schema validation results
- Policy check results (pass/fail for each rule)
- Detailed breakdown of any issues found

---

### 4. Upload Single SBOM

Upload a single BOM file interactively.

```bash
python main.py upload --file <path_to_sbom>
```

**Examples:**
```bash
# Upload a JSON SBOM
python main.py upload --file sbom.json

# Upload an XML SBOM
python main.py upload --file sbom.xml
```

**Interactive prompts:**
- Choose to upload to existing project or create new
- Auto-bumps version if uploading to existing project
- Enter project name and version for new projects

---

### 5. Bulk Upload Host SBOMs

Upload multiple Host SBOMs with automatic project naming and tagging.

```bash
python main.py bulk-upload-host --folder <path> --tags <excel_path> [options]
```

**Required Arguments:**
| Argument | Description |
|----------|-------------|
| `--folder <path>` | Folder containing Host SBOM JSON files (scans recursively) |
| `--tags <excel_path>` | Excel file mapping account numbers to tags |

**Optional Arguments:**
| Argument | Description | Default |
|----------|-------------|---------|
| `--version <ver>` | Project version | 1.0 |
| `--dry-run` | Simulate upload without making API calls | false |
| `--limit <n>` | Limit number of files to process (0 = no limit) | 0 |

**Examples:**
```bash
# Basic bulk upload
python main.py bulk-upload-host --folder "Host/Part_1" --tags "Account data.xlsx"

# Bulk upload with specific version
python main.py bulk-upload-host --folder "Host/Part_1" --tags "Account data.xlsx" --version 2.0

# Dry run to simulate upload
python main.py bulk-upload-host --folder "Host/Part_1" --tags "Account data.xlsx" --dry-run

# Limit to first 100 files
python main.py bulk-upload-host --folder "Host/Part_1" --tags "Account data.xlsx" --limit 100

# Combined options
python main.py bulk-upload-host --folder "Host/Part_1" --tags "Account data.xlsx" --version 1.5 --dry-run --limit 50
```

**Filename Format:**
Host SBOMs should follow this naming convention:
```
<account_number>_<ip>_<hash>_<timestamp>.json
```
Example: `22206351557_ip-10-53-64-89_4df91bb73d15db3b_2026-02-17T08-16-56Z.json`

**Project Naming:**
Projects are automatically named as: `<account_number>_Host_<ip>`
Example: `22206351557_Host_ip-10-53-64-89`

---

### 6. Preview Host Parsing

Preview how filenames will be parsed without uploading.

```bash
python main.py preview-host --folder <path> --tags <excel_path> [--limit <n>]
```

**Required Arguments:**
| Argument | Description |
|----------|-------------|
| `--folder <path>` | Folder containing Host SBOM files |
| `--tags <excel_path>` | Excel file with account number to tags mapping |

**Optional Arguments:**
| Argument | Description | Default |
|----------|-------------|---------|
| `--limit <n>` | Number of files to preview | 10 |

**Examples:**
```bash
# Preview first 10 files (default)
python main.py preview-host --folder "Host/Part_1" --tags "Account data.xlsx"

# Preview first 50 files
python main.py preview-host --folder "Host/Part_1" --tags "Account data.xlsx" --limit 50
```

---

### 7. Extract All Policy Violations

Export all policy violations from Dependency-Track to Excel and CSV.

```bash
python extract_policy_violations.py
```

**Output:** Creates two files:
- `policy_violations_<timestamp>.xlsx` - Excel file with:
  - **Policy Violations sheet** - All violations with full details
  - **Summary sheet** - Statistics by policy, project, and type
- `policy_violations_<timestamp>.csv` - CSV file with all violations

**Columns included:**
- Violation UUID, Type, State, Suppressed
- Policy Name, UUID, Violation State
- Condition UUID, Subject, Operator, Value
- Component UUID, Name, Version, Group, PURL, CPE, License
- Project UUID, Name, Version
- Tags (up to 10 tag columns)

---

### 8. Extract Policy Violations for Specific Projects

Export policy violations for specific projects only.

```bash
python extract_selected_projects_violations.py
```

**Note:** Edit the `TARGET_PROJECTS` list in the script to specify which projects to include:
```python
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
```

**Output:** Creates `policy_violations_selected_projects_<timestamp>.xlsx` with violations only for matched projects.

---

### 9. Delete All Projects

⚠️ **DANGER:** Delete all projects from Dependency-Track. Use with caution!

```bash
python delete_all_projects.py
```

**Warning:** This will permanently delete ALL projects in your Dependency-Track instance.

---

### 10. Validate Failed SBOMs

Analyze and create a report for failed SBOM uploads.

```bash
python validate_failed.py
```

**Output:** Creates `failed_sboms_validation_report.xlsx` with validation details.

---

## Excel Tags File Format

The tags Excel file should have:
- **Column A**: Account Number
- **Remaining columns**: Tags to apply

| AccountNumber | Tag1 | Tag2 | Tag3 |
|---------------|------|------|------|
| 22206351557 | prod | aws | critical |
| 102809085638 | dev | azure | |

---

## Project Structure

```
DSBOMUpload/
├── main.py                              # CLI entry point
├── config.py                            # Configuration (environment variables)
├── project.py                           # Project management (create/list projects)
├── bom.py                               # BOM upload functionality
├── bulk_upload.py                       # Bulk upload with tag mapping
├── export_projects_to_excel.py          # Export projects to Excel (with rich output)
├── simple_export_projects.py            # Export projects to Excel (simple version)
├── extract_policy_violations.py         # Extract all policy violations
├── extract_selected_projects_violations.py  # Extract violations for specific projects
├── delete_all_projects.py               # Delete all projects (dangerous!)
├── validate_failed.py                   # Validate failed SBOMs
├── requirements.txt                     # Python dependencies
├── utils/
│   ├── cli_utils.py                     # CLI helper functions
│   └── file_utils.py                    # File utility functions
├── validator/
│   ├── policy_enforcer.py               # Policy enforcement
│   ├── schema_validator.py              # Schema validation
│   ├── semantic_validator.py            # Semantic validation
│   └── policies/
│       └── policy.yaml                  # Policy configuration
└── schemas/
    ├── json/                            # JSON schemas for validation
    │   ├── bom-1.4.schema.json
    │   └── bom-1.6.schema.json
    └── xml/                             # XML schemas for validation
        ├── bom-1.4.xsd
        └── spdx.xsd
```

---

## Quick Reference

| Command | Description |
|---------|-------------|
| `python main.py list-projects` | List all projects |
| `python main.py export-projects-excel` | Export projects to Excel |
| `python main.py validate --file <path>` | Validate SBOM locally (schema + policy) |
| `python main.py upload --file <path>` | Upload single SBOM |
| `python main.py bulk-upload-host --folder <path> --tags <excel>` | Bulk upload Host SBOMs |
| `python main.py preview-host --folder <path> --tags <excel>` | Preview Host parsing |
| `python extract_policy_violations.py` | Export all policy violations |
| `python extract_selected_projects_violations.py` | Export violations for specific projects |
| `python delete_all_projects.py` | Delete all projects (⚠️ dangerous) |
| `python validate_failed.py` | Validate failed SBOMs |

---

## License

MIT
