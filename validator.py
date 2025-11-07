import os
import json
import requests
from rich.console import Console
from rich.table import Table
from jsonschema import validate as json_validate, ValidationError
import xml.etree.ElementTree as ET
from lxml import etree

console = Console()

CYCLONEDX_SCHEMA_BASE = "https://raw.githubusercontent.com/CycloneDX/specification/master/schema"
SCHEMA_DIR = os.path.join(os.path.dirname(__file__), "schemas")


def ensure_schema_exists(schema_format: str, spec_version: str):
    """
    Ensure the CycloneDX schema file for the given version/format exists locally.
    """
    os.makedirs(os.path.join(SCHEMA_DIR, schema_format), exist_ok=True)

    if schema_format == "json":
        filename = f"bom-{spec_version}.schema.json"
    else:
        filename = f"bom-{spec_version}.xsd"

    local_path = os.path.join(SCHEMA_DIR, schema_format, filename)

    if not os.path.exists(local_path):
        url = f"{CYCLONEDX_SCHEMA_BASE}/{filename}"
        console.print(f"[yellow]🔽 Downloading CycloneDX schema:[/yellow] {url}")
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                with open(local_path, "wb") as f:
                    f.write(response.content)
                console.print(f"[green]✅ Schema cached locally:[/green] {local_path}")
            else:
                console.print(f"[red]⚠️ Failed to fetch schema (HTTP {response.status_code})[/red]")
                return None
        except Exception as e:
            console.print(f"[red]⚠️ Schema download failed:[/red] {e}")
            return None

    return local_path


def detect_bom_format_and_version(file_path: str):
    """
    Detect if BOM is JSON or XML and extract specVersion.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            first_char = f.read(1)
            f.seek(0)
            if first_char == "{":
                # JSON BOM
                data = json.load(f)
                return "json", data.get("specVersion", None), data
            else:
                # XML BOM
                tree = ET.parse(f)
                root = tree.getroot()

                # Extract specVersion from namespace
                xmlns = root.tag[root.tag.find("{")+1:root.tag.find("}")]
                spec_version = None
                if xmlns.startswith("http://cyclonedx.org/schema/bom/"):
                    spec_version = xmlns.split("/")[-1]  # e.g., "1.4"

                # Fallback to version attribute
                if not spec_version:
                    spec_version = root.attrib.get("version")

                return "xml", spec_version, root
    except Exception as e:
        console.print(f"[red]❌ Format detection failed:[/red] {e}")
        return None, None, None


def level1_check(file_path: str):
    """
    Level 1: Basic file checks.
    """
    if not os.path.exists(file_path):
        return False, "File not found."
    if os.path.getsize(file_path) == 0:
        return False, "File is empty."
    return True, "File exists and is not empty."


def level2_check(format_type, spec_version, bom_data):
    """
    Level 2: Structural field validation.
    """
    if not format_type or not spec_version:
        return False, "specVersion or format missing."

    if format_type == "json":
        required_fields = ["bomFormat", "specVersion", "components"]
        for field in required_fields:
            if field not in bom_data:
                return False, f"Missing key: {field}"
        if bom_data["bomFormat"] != "CycloneDX":
            return False, "Invalid bomFormat, must be 'CycloneDX'."
        if not isinstance(bom_data.get("components", []), list):
            return False, "components must be a list."
    else:
        # XML minimal structural check
        if not bom_data.tag.lower().endswith("bom"):
            return False, "Root element must be <bom>."
        ns = {"ns": "http://cyclonedx.org/schema/bom/" + spec_version}
        components = bom_data.findall(".//ns:components", ns)
        if not components:
            return False, "Missing <components> element."
    return True, "Structure looks valid."


def level3_check(file_path: str, format_type: str, spec_version: str):
    """
    Level 3: Schema validation (strict compliance).
    """
    schema_path = ensure_schema_exists(format_type, spec_version)
    if not schema_path:
        return None, "Schema not found; skipping strict validation."

    try:
        if format_type == "json":
            with open(schema_path, "r", encoding="utf-8") as s:
                schema = json.load(s)
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            json_validate(instance=data, schema=schema)
        else:
            xmlschema_doc = etree.parse(schema_path)
            xmlschema = etree.XMLSchema(xmlschema_doc)
            xml_doc = etree.parse(file_path)
            xmlschema.assertValid(xml_doc)
        return True, f"BOM is valid according to CycloneDX {spec_version} schema."
    except ValidationError as e:
        return False, f"JSON schema validation failed: {e.message}"
    except etree.DocumentInvalid as e:
        return False, f"XML schema validation failed: {e}"
    except Exception as e:
        return False, f"Unexpected error during validation: {e}"


def validate_bom_file(file_path: str):
    """
    Runs Level 1, 2, and 3 validation with rich output.
    """
    console.print(f"\n[bold cyan]🔍 Validating BOM file:[/bold cyan] {file_path}\n")

    results = []

    # Level 1
    lvl1_pass, lvl1_msg = level1_check(file_path)
    results.append(("Level 1: File Check", lvl1_pass, lvl1_msg))
    if not lvl1_pass:
        display_results(results)
        return False

    # Detect format + version
    format_type, spec_version, bom_data = detect_bom_format_and_version(file_path)
    if not format_type:
        results.append(("Format Detection", False, "Could not determine format or specVersion."))
        display_results(results)
        return False

    # Level 2
    lvl2_pass, lvl2_msg = level2_check(format_type, spec_version, bom_data)
    results.append(("Level 2: Structure Check", lvl2_pass, lvl2_msg))

    # Level 3
    lvl3_pass, lvl3_msg = level3_check(file_path, format_type, spec_version)
    if lvl3_pass is None:
        results.append(("Level 3: Schema Validation", True, "Skipped (schema not found)"))
    else:
        results.append(("Level 3: Schema Validation", lvl3_pass, lvl3_msg))

    display_results(results)
    return all(passed for _, passed, _ in results if passed is not None)


def display_results(results):
    """
    Display validation results in a formatted table.
    """
    table = Table(title="BOM Validation Summary", show_header=True, header_style="bold magenta")
    table.add_column("Check")
    table.add_column("Status", style="bold")
    table.add_column("Message", style="dim")

    for check, passed, msg in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        table.add_row(check, status, msg)

    console.print(table)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="CycloneDX BOM Validator")
    parser.add_argument("--file", required=True, help="Path to BOM file")
    args = parser.parse_args()

    success = validate_bom_file(args.file)
    if success:
        console.print("✅ BOM validation passed!")
    else:
        console.print("❌ BOM validation failed!")
