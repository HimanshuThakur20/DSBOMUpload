# validator/schema_validator.py
import os
import json
import time
import requests
from typing import Optional, Tuple, List, Union
from rich.console import Console
from lxml import etree
from jsonschema import validate as json_validate, ValidationError

console = Console()

BASE_DIR = os.path.dirname(__file__)
SCHEMAS_DIR = os.path.join(BASE_DIR, "schemas")
JSON_SCHEMA_DIR = os.path.join(SCHEMAS_DIR, "json")
XML_SCHEMA_DIR = os.path.join(SCHEMAS_DIR, "xml")

CYCLONEDX_JSON_BASE = "https://cyclonedx.org/schema"
CYCLONEDX_XSD_BASE = (
    "https://raw.githubusercontent.com/CycloneDX/specification/master/schema"
)

SPDX_JSON_MAP = {
    "2.2": "https://raw.githubusercontent.com/spdx/spdx-spec/v2.2/schemas/spdx-json-schema.json",
    "2.3": "https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json",
}

SPDX_XSD_URL = "https://raw.githubusercontent.com/spdx/spdx-spec/master/schemas/spdx.xsd"

DEFAULT_HEADERS = {"User-Agent": "DSBOMUpload-schema-validator/1.0"}
MAX_RETRIES = 3
RETRY_DELAY = 1.0


# =====================================================
# DIR SETUP
# =====================================================
def ensure_dirs():
    os.makedirs(JSON_SCHEMA_DIR, exist_ok=True)
    os.makedirs(XML_SCHEMA_DIR, exist_ok=True)


# =====================================================
# DOWNLOAD FILE (safe retry)
# =====================================================
def download_file(url: str, local_path: str) -> bool:
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(url, headers=DEFAULT_HEADERS, timeout=20)
            if resp.status_code == 200:
                with open(local_path, "wb") as fw:
                    fw.write(resp.content)
                return True

            if resp.status_code == 404:
                return False

        except Exception:
            pass

        time.sleep(RETRY_DELAY)

    return False


# =====================================================
# AUTO-PATCH BROKEN CycloneDX 1.4 XSD
# =====================================================
def patch_broken_spdx_type(xsd_path: str):
    """
    CycloneDX 1.4 XSD incorrectly references spdx:licenseId which does not exist.
    This replaces it with xs:string so schema validation succeeds.
    """

    try:
        with open(xsd_path, "r", encoding="utf-8") as f:
            text = f.read()
    except Exception:
        return False

    if "spdx:licenseId" not in text:
        return False  # nothing to fix

    patched_text = text.replace(
        'type="spdx:licenseId"',
        'type="xs:string"'
    )

    try:
        with open(xsd_path, "w", encoding="utf-8") as f:
            f.write(patched_text)

        console.print(
            f"[yellow][schema-fix][/yellow] Patched broken SPDX type in {xsd_path}"
        )
        return True

    except Exception:
        return False


# =====================================================
# JSON SCHEMA
# =====================================================
def ensure_json_schema(spec_version: str, bom_type="cyclonedx", auto_download=True):
    ensure_dirs()

    if bom_type == "cyclonedx":
        filename = f"bom-{spec_version}.schema.json"
        local_path = os.path.join(JSON_SCHEMA_DIR, filename)

        if os.path.exists(local_path):
            return local_path

        if auto_download:
            url = f"{CYCLONEDX_JSON_BASE}/{filename}"
            if download_file(url, local_path):
                return local_path

            fallback_url = f"{CYCLONEDX_XSD_BASE}/{filename}"
            if download_file(fallback_url, local_path):
                return local_path

        return None

    if bom_type == "spdx":
        version = (spec_version or "").replace("SPDX-", "").strip()
        if version in SPDX_JSON_MAP:
            url = SPDX_JSON_MAP[version]
            filename = f"spdx-{version}.json"
            local_path = os.path.join(JSON_SCHEMA_DIR, filename)

            if os.path.exists(local_path):
                return local_path

            if auto_download and download_file(url, local_path):
                return local_path

        return None

    return None


# =====================================================
# XSD IMPORT RESOLUTION
# =====================================================
def download_schema_if_missing(url: str) -> str:
    filename = url.split("/")[-1]
    local_path = os.path.join(XML_SCHEMA_DIR, filename)

    if os.path.exists(local_path):
        return local_path

    console.print(f"[yellow][schema-loader][/yellow] Downloading: {url}")

    if download_file(url, local_path):
        return local_path

    raise RuntimeError(f"Unable to download required XSD: {url}")


def resolve_imports(schema_doc: etree._ElementTree):
    xs_ns = {"xs": "http://www.w3.org/2001/XMLSchema"}

    for imp in schema_doc.findall(".//xs:import", xs_ns) + schema_doc.findall(".//xs:include", xs_ns):
        schema_loc = imp.attrib.get("schemaLocation")
        if not schema_loc:
            continue

        # Already local?
        if os.path.exists(schema_loc):
            continue

        # Remote URL?
        if schema_loc.startswith("http://") or schema_loc.startswith("https://"):
            local = download_schema_if_missing(schema_loc)
            imp.attrib["schemaLocation"] = local
            continue

        # Relative → try CycloneDX repo
        remote_url = f"{CYCLONEDX_XSD_BASE}/{schema_loc}"
        try:
            local = download_schema_if_missing(remote_url)
            imp.attrib["schemaLocation"] = local
        except Exception:
            local_rel = os.path.join(XML_SCHEMA_DIR, schema_loc)
            if os.path.exists(local_rel):
                imp.attrib["schemaLocation"] = local_rel


def load_xml_schema_resolved(xsd_path: str) -> etree.XMLSchema:
    parser = etree.XMLParser(remove_blank_text=True)
    doc = etree.parse(xsd_path, parser)

    resolve_imports(doc)

    try:
        return etree.XMLSchema(doc)
    except Exception as ex:
        raise RuntimeError(f"XMLSchema build failed: {ex}")


# =====================================================
# Ensure XSD + auto-patch
# =====================================================
def ensure_xsd_with_imports(spec_version: str, auto_download=True):
    ensure_dirs()

    filename = f"bom-{spec_version}.xsd"
    local_path = os.path.join(XML_SCHEMA_DIR, filename)

    if not os.path.exists(local_path):
        if not auto_download:
            return None

        url = f"{CYCLONEDX_XSD_BASE}/{filename}"
        if not download_file(url, local_path):
            return None

    # ALWAYS: auto-patch schema (Fix B)
    patch_broken_spdx_type(local_path)

    return local_path


# =====================================================
# VALIDATION FUNCTIONS
# =====================================================
def validate_json_schema(json_path, schema_path):
    try:
        with open(schema_path, "r", encoding="utf-8") as s:
            schema = json.load(s)

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        json_validate(data, schema)
        return True, "JSON BOM is valid."

    except ValidationError as e:
        loc = list(e.path)
        return False, f"JSON schema error at {loc}: {e.message}"

    except Exception as e:
        return False, f"JSON schema validation failure: {e}"


def validate_xml_schema(xml_path, xsd_path):
    try:
        schema = load_xml_schema_resolved(xsd_path)
    except Exception as ex:
        return False, [str(ex)]

    parser = etree.XMLParser(resolve_entities=False, no_network=True)

    try:
        xml_doc = etree.parse(xml_path, parser)
    except Exception as ex:
        return False, [f"XML parse error: {ex}"]

    if schema.validate(xml_doc):
        return True, "XML BOM is valid."

    # Format errors
    return False, [str(e) for e in schema.error_log]


# =====================================================
# MAIN ENTRYPOINT
# =====================================================
def validate_against_schema(file_path, auto_download=True):
    if not os.path.exists(file_path):
        return False, f"File does not exist: {file_path}"

    with open(file_path, "r", encoding="utf-8") as f:
        first = f.read(100).lstrip()

    # JSON
    if first.startswith("{"):
        data = json.load(open(file_path, "r", encoding="utf-8"))

        if data.get("bomFormat", "").lower() == "cyclonedx":
            version = data.get("specVersion")
            schema = ensure_json_schema(version, "cyclonedx", auto_download)
            if not schema:
                return False, f"No CycloneDX schema for version {version}"
            return validate_json_schema(file_path, schema)

        if "spdxVersion" in data:
            version = data.get("spdxVersion")
            schema = ensure_json_schema(version, "spdx", auto_download)
            if not schema:
                return False, f"No SPDX schema for version {version}"
            return validate_json_schema(file_path, schema)

        return False, "Unknown JSON SBOM type."

    # XML
    try:
        doc = etree.parse(file_path)
        root = doc.getroot()
    except Exception as ex:
        return False, f"XML parse error: {ex}"

    ns = root.nsmap.get(None, "")

    if "cyclonedx.org/schema/bom" in ns:
        version = ns.split("/")[-1]
        xsd = ensure_xsd_with_imports(version, auto_download)
        if not xsd:
            return False, f"No CycloneDX XSD for version {version}"
        return validate_xml_schema(file_path, xsd)

    if "spdx" in ns.lower():
        local = os.path.join(XML_SCHEMA_DIR, "spdx.xsd")
        if not os.path.exists(local) and auto_download:
            download_file(SPDX_XSD_URL, local)
        if os.path.exists(local):
            return validate_xml_schema(file_path, local)
        return False, "Missing SPDX XSD."

    return False, f"Unknown XML SBOM namespace: {ns}"
