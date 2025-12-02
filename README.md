# SBOM Validator & Dependency-Track CLI

A complete command-line toolkit for validating SBOM files, enforcing policy rules, performing ecosystem checks, and integrating with Dependency-Track.

This tool provides:

SBOM file validation (CycloneDX JSON/XML, SPDX JSON/XML)

Schema validation with automatic schema fetching

Semantic + policy-driven validation

deps.dev package existence verification

Uploading SBOMs into Dependency-Track

Project/version management

Setup & First-Time Configuration
🚀 1. Prerequisites

Before using this tool, ensure you have:

Python 3.9+

Dependency-Track server (Self-hosted or SaaS)

An API key with correct permissions

A CycloneDX or SPDX SBOM (JSON or XML)

🔐 2. Dependency-Track Setup

To upload SBOMs programmatically, create a restricted-scoped API key.

Required roles / permissions

The API key must belong to a user or team that has:

Permission	Purpose
PROJECT_CREATE	Create new projects when needed
PORTFOLIO_MANAGEMENT	Update project information
BOM_UPLOAD	Upload SBOMs to projects
READ_PROJECT	Read project metadata
VULNERABILITY_ANALYSIS	Optional, for future extensions

Alternatively, you can assign one of these roles:

Automation

Continuous Integration

Portfolio Manager

⚠️ Admin role is not required and not recommended.

🌐 3. Configure Base URL and API Key

Your tool reads settings from environment variables:

DTRACK_BASE_URL=https://your-dependency-track-url
DTRACK_API_KEY=your_api_key_here


You can set them permanently:

Linux / macOS
export DTRACK_BASE_URL="https://dtrack.company.com"
export DTRACK_API_KEY="ABC123APIKEY"

Windows PowerShell
setx DTRACK_BASE_URL "https://dtrack.company.com"
setx DTRACK_API_KEY "ABC123APIKEY"

Windows CMD
set DTRACK_BASE_URL=https://dtrack.company.com
set DTRACK_API_KEY=ABC123APIKEY


The tool automatically reads these values when running uploads.

🛠️ 4. How Uploading Works

When you run:

python -m main upload --file sbom.json


The tool:

Checks whether you want to upload to:

an existing project

or a new project

Validates whether the project exists

if found → uses its UUID

if not → creates one

Generates or bumps the version if uploading again

Uploads the SBOM via Dependency-Track API:

POST /api/v1/bom


Prints confirmation and project metadata

📦 5. Example: Uploading an SBOM
python -m main upload --file myapp_sbom.json


Output:

Do you want to upload to an existing project? (y/n)
Auto-bumping version: 1.2 → 1.3
BOM uploaded successfully.
Project: MyApp
Version: 1.3

🧪 6. SBOM Validation (Local Only)

You can validate any SBOM without uploading:

python -m main validate --file sbom.xml


Validation includes:

File reading / format detection

Schema validation (CycloneDX & SPDX; dynamic XSD loading)

Semantic validation

Policy enforcement

deps.dev reality checks (with planned fallbacks: osv.dev, Libraries.io, Maven Central, PyPI, npm registry, etc.)

🧩 7. Environment Variable Summary
Variable	Description
DTRACK_BASE_URL	URL of Dependency-Track (must be accessible)
DTRACK_API_KEY	API key with required permissions
(future) VALIDATOR_POLICY_FILE	Override default policy.yaml
(future) VALIDATOR_DISABLE_DEPSDEV	Skip deps.dev checks
📁 8. Optional: Config via .env file

Create a .env file:

DTRACK_BASE_URL=https://dtrack.company.com
DTRACK_API_KEY=ABC123APIKEY


Tool automatically loads it when python-dotenv is installed.

Features
1. SBOM Detection & Schema Validation

Detects JSON/XML formats

Supports CycloneDX 1.2–1.7, SPDX 2.2–2.3

Automatically downloads missing schemas

Fixes CycloneDX 1.4 XML SPDX import namespace bug

Dynamic JSON Schema + XSD validation

2. Semantic Validation

Implemented in semantic_validator.py:

Required timestamp, author

Missing/invalid versions

Missing/invalid licenses

Missing PURLs

Missing suppliers

Invalid SPDX license identifiers

Missing dependencies

Duplicate component checks (future)

Empty fields (future)

3. Policy Enforcement

Driven by policy.yaml:

Rule id, display_name, category, severity, strict

Supports severities: error, warning, notice, off

CI Minimal summary + Full Detailed table

ANSI-colored output (green/yellow/red)

4. deps.dev Ecosystem Verification

Performs a real-time package existence check using https://deps.dev
.
Currently supports:

Maven

npm

PyPI

Go

NuGet

(Composer & generic packages: partial support)

5. Dependency-Track Integration

List existing projects

Auto-bump project version

Create new project

Upload SBOM

Uses Dependency-Track API v1

Installation
Requirements

Python 3.10+

Dependency-Track (optional, for upload features)

Install Python dependencies
pip install -r requirements.txt


Required libs:

rich
requests
pyyaml
jsonschema
lxml
packaging

Project Structure
DSBOMUpload/
  main.py
  sbom_validator.py
  validator/
    schema_validator.py
    semantic_validator.py
    policy_enforcer.py
    depsdev_validator.py
    policies/
      policy.yaml
  project.py
  bom.py
  utils/
    file_utils.py
    cli_utils.py

CLI Commands
1. List Projects (Dependency-Track)
python -m main list-projects


Displays all projects configured in Dependency-Track.

2. Validate SBOM
python -m main validate --file <path>


Examples:

python -m main validate --file mysbom.json
python -m main validate --file containerbom.xml


The validation process includes:

PHASE 1 — File / Parsing / SBOM Detection

Detect CycloneDX or SPDX

Detect JSON/XML

Load SBOM safely

Extract specVersion

PHASE 2 — Schema Validation

Downloads XSD/JSON schemas automatically

Fixes CycloneDX 1.4 SPDX import namespace

Validates XML (XSD) and JSON (JSON Schema)

PHASE 3 — Semantic + Policy Enforcement

Runs rule checks from semantic validator

Applies policy.yaml (severity, strict, category)

Produces two outputs:

CI minimal summary

Detailed annotated table

Severity behavior:

Severity	Result	Blocks Validation
error	FAIL	Yes
warning	WARN	No
notice	WARN	No
off	SKIP	Ignored
PHASE 4 — deps.dev Package Reality Check

Verifies each PURL against deps.dev.

Example result:

pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1 → PASS
pkg:composer/vendor/package@latest → FAIL (not supported)

3. Upload SBOM to Dependency-Track
python -m main upload --file <path>


Choose existing project or create new

Auto-bump version if existing

Uploads the SBOM

Configuration
Policy Rules — validator/policies/policy.yaml

Each rule:

require_purl:
  id: PURL_MISSING
  display_name: "PURL Missing"
  category: identity
  description: "Component missing Package URL (purl)"
  severity: error
  strict: true


Categories:

metadata

components

license

identity

dependencies

hygiene

Modify severities as required.

deps.dev Coverage

deps.dev supports:

Ecosystem	Supported
Maven Central	✓
npm	✓
PyPI	✓
Go	✓
NuGet	✓
Composer	Partial
Generic PURLs	✗

For unsupported ecosystems, the tool will later include fallbacks such as:

Maven Central API

Libraries.io

OSS Index (Sonatype)

Example Output (Clean GitHub Console)
Successful Validation
PHASE 2 — Schema Validation
✔ Schema validation passed

Failed Rule
Rule: require_author
Severity: error
Status: FAIL
Message: No authors defined in SBOM

Development
Code formatting
black .

Tests (if added)
pytest -v

License

MIT
