# validator/schema_validator.py

import os
import json
import time
import requests
from typing import Optional, Tuple, List
from rich.console import Console
from lxml import etree
from jsonschema import validate as json_validate, ValidationError

console = Console()

BASE_DIR = os.path.dirname(__file__)
SCHEMAS_DIR = os.path.join(BASE_DIR, "..", "schemas")

JSON_SCHEMA_DIR = os.path.join(SCHEMAS_DIR, "json")
XML_SCHEMA_DIR = os.path.join(SCHEMAS_DIR, "xml")

# CycloneDX official schema repos
CYCLONEDX_JSON_BASE = "https://cyclonedx.org/schema"
CYCLONEDX_XSD_BASE = "https://raw.githubusercontent.com/CycloneDX/specification/master/schema"

# SPDX schema repos
SPDX_JSON_BASE = "https://raw.githubusercontent.com/spdx/spdx-spec"
SPDX_XML_BASE  = "https://raw.githubusercontent.com/spdx/spdx-spec"

DEFAULT_HEADERS = {"User-Agent": "DSBOMUpload-schema-validator/1.0"}
MAX_RETRIES = 3
RETRY_DELAY = 1.0


# =============================================================
#  Ensure folder structure
# =============================================================
def _ensure_dirs():
    os.makedirs(JSON_SCHEMA_DIR, exist_ok=True)
    os.makedirs(XML_SCHEMA_DIR, exist_ok=True)


# =============================================================
#  Download with retry
# =============================================================
def _download_file(url: str, local_path: str) -> bool:
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=20)
            if resp.status_code == 200:
                with open(local_path, "wb") as fw:
                    fw.write(resp.content)
                console.print(f"[green]✔ Downloaded:[/green] {url}")
                return True

            elif resp.status_code == 404:
                return False

            console.print(f"[yellow]⚠ HTTP {resp.status_code}: {url}[/yellow]")

        except Exception as e:
            console.print(f"[yellow]⚠ Attempt {attempt} failed: {e}[/yellow]")

        time.sleep(RETRY_DELAY)

    console.print(f"[red]❌ Failed to download schema: {url}[/red]")
    return False


# =============================================================
#  JSON Schema Resolver (CycloneDX + SPDX)
# =============================================================
def _resolve_json_schema(spec_version: str, bom_type: str) -> Optional[str]:
    _ensure_dirs()

    if bom_type == "cyclonedx":
        filename = f"bom-{spec_version}.schema.json"
        local_path = os.path.join(JSON_SCHEMA_DIR, filename)

        if os.path.exists(local_path):
            return local_path

        url = f"{CYCLONEDX_JSON_BASE}/{filename}"
        console.print(f"[yellow]🔽 Fetching CycloneDX JSON Schema: {url}[/yellow]")
        if _download_file(url, local_path):
            return local_path

        return None

    elif bom_type == "spdx":
        # Example: v2.3/schemas/spdx-schema.json
        version_folder = f"v{spec_version}"
        filename = "spdx-schema.json"
        url = f"{SPDX_JSON_BASE}/{version_folder}/schemas/{filename}"

        local_path = os.path.join(JSON_SCHEMA_DIR, f"spdx-{spec_version}.json")

        console.print(f"[yellow]🔽 Fetching SPDX JSON Schema: {url}[/yellow]")
        if _download_file(url, local_path):
            return local_path

        return None

    return None


# =============================================================
#  XML Schema Resolver (CycloneDX + SPDX)
# =============================================================
def _resolve_xml_schema(spec_version: str, bom_type: str) -> Optional[str]:
    _ensure_dirs()

    if bom_type == "cyclonedx":
        filename = f"bom-{spec_version}.xsd"
        local_path = os.path.join(XML_SCHEMA_DIR, filename)

        if os.path.exists(local_path):
            return local_path

        url = f"{CYCLONEDX_XSD_BASE}/{filename}"
        console.print(f"[yellow]🔽 Fetching CycloneDX XSD: {url}[/yellow]")
        if _download_file(url, local_path):
            return local_path

        return None

    elif bom_type == "spdx":
        filename = "spdx.xsd"
        local_path = os.path.join(XML_SCHEMA_DIR, f"spdx-{spec_version}.xsd")

        url = f"{SPDX_XML_BASE}/v{spec_version}/schemas/{filename}"
        console.print(f"[yellow]🔽 Fetching SPDX XSD: {url}[/yellow]")
        if _download_file(url, local_path):
            return local_path

        return None

    return None


# =============================================================
#  JSON Schema Validation
# =============================================================
def _validate_json(json_path: str, schema_path: str):
    try:
        with open(schema_path, "r") as s:
            schema = json.load(s)

        with open(json_path, "r") as f:
            data = json.load(f)

        json_validate(data, schema)
        return True, ["JSON schema OK"]

    except ValidationError as e:
        return False, [f"JSON schema validation failed: {e.message}"]

    except Exception as e:
        return False, [f"JSON validation error: {str(e)}"]


# =============================================================
#  XML Schema Validation
# =============================================================
def _validate_xml(xml_path: str, schema_path: str):
    try:
        schema_doc = etree.parse(schema_path)
        schema = etree.XMLSchema(schema_doc)

        doc = etree.parse(xml_path)
        schema.assertValid(doc)
        return True, ["XML schema OK"]

    except etree.DocumentInvalid as e:
        msgs = []
        for err in e.error_log:
            msgs.append(f"Line {err.line}: {err.message.strip()}")
        return False, msgs

    except Exception as e:
        return False, [f"XML validation error: {str(e)}"]


# =============================================================
#  PUBLIC ENTRY POINT
# =============================================================
def validate_against_schema(file_path: str) -> Tuple[bool, List[str]]:
    """
    Automatically detects:
        - BOM type (CycloneDX / SPDX)
        - Format (JSON / XML)
        - specVersion
    Fetches schema dynamically and validates.
    """

    if not os.path.exists(file_path):
        return False, [f"File not found: {file_path}"]

    # detect JSON vs XML by first non-whitespace character
    with open(file_path, "r", encoding="utf-8") as fh:
        initial = fh.read(2048).lstrip()

    is_json = initial.startswith("{")

    # --- JSON CASE ---
    if is_json:
        try:
            data = json.loads(initial)
        except Exception:
            data = json.load(open(file_path, "r"))

        # CycloneDX JSON
        if data.get("bomFormat", "").lower() == "cyclonedx":
            bom_type = "cyclonedx"
            spec_version = data.get("specVersion")

        # SPDX JSON
        elif data.get("spdxVersion"):
            bom_type = "spdx"
            spec_version = data.get("spdxVersion").replace("SPDX-", "")

        else:
            return False, ["Could not detect SBOM type"]

        schema_path = _resolve_json_schema(spec_version, bom_type)
        if not schema_path:
            return False, [f"No JSON schema found for {bom_type} {spec_version}"]

        return _validate_json(file_path, schema_path)

    # --- XML CASE ---
    try:
        doc = etree.parse(file_path)
        root = doc.getroot()
        ns = root.nsmap.get(None, "")
    except Exception as e:
        return False, [f"XML parse error: {e}"]

    # CycloneDX XML namespace
    if "cyclonedx" in ns or "bom" in ns:
        bom_type = "cyclonedx"
        spec_version = ns.split("/")[-1]

    # SPDX XML namespace
    elif "spdx" in ns:
        bom_type = "spdx"
        spec_version = root.get("version", "")

    else:
        return False, ["Could not detect SBOM type"]

    schema_path = _resolve_xml_schema(spec_version, bom_type)
    if not schema_path:
        return False, [f"No XSD schema found for {bom_type} {spec_version}"]

    return _validate_xml(file_path, schema_path)
