import os
import json
import requests
from rich.console import Console
from jsonschema import validate as json_validate, ValidationError
import xml.etree.ElementTree as ET
from lxml import etree

console = Console()

# Base URL for official CycloneDX schemas
CYCLONEDX_SCHEMA_BASE = "https://raw.githubusercontent.com/CycloneDX/specification/master/schema"

# Local cache directory for schemas
SCHEMA_DIR = os.path.join(os.path.dirname(__file__), "schemas")


def ensure_schema_exists(schema_format: str, spec_version: str):
    """
    Ensure the CycloneDX schema file for the given version/format exists locally.
    If not, download it from GitHub.
    """
    os.makedirs(os.path.join(SCHEMA_DIR, schema_format), exist_ok=True)

    if schema_format == "json":
        filename = f"bom-{spec_version}.schema.json"
    elif schema_format == "xml":
        filename = f"bom-{spec_version}.xsd"
    else:
        raise ValueError(f"Unknown schema format: {schema_format}")

    local_path = os.path.join(SCHEMA_DIR, schema_format, filename)
    if not os.path.exists(local_path):
        url = f"{CYCLONEDX_SCHEMA_BASE}/{filename}"
        console.print(f"[yellow]🔽 Downloading CycloneDX schema:[/yellow] {url}")
        response = requests.get(url, timeout=30)

        if response.status_code == 200:
            with open(local_path, "wb") as f:
                f.write(response.content)
            console.print(f"[green]✅ Schema cached locally:[/green] {local_path}")
        else:
            console.print(f"[red]⚠️ Failed to fetch schema (HTTP {response.status_code})[/red]")
            return None

    return local_path


def detect_bom_format_and_version(file_path: str):
    """
    Detect if BOM is JSON or XML and extract specVersion.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        first_char = f.read(1)
        f.seek(0)
        if first_char == "{":
            # JSON BOM
            try:
                bom_data = json.load(f)
                spec_version = bom_data.get("specVersion", None)
                return "json", spec_version
            except json.JSONDecodeError:
                console.print("[red]❌ Invalid JSON structure.[/red]")
                return "json", None
        else:
            # XML BOM
            try:
                tree = ET.parse(f)
                root = tree.getroot()
                spec_version = root.attrib.get("version")
                return "xml", spec_version
            except Exception as e:
                console.print(f"[red]❌ XML parsing error:[/red] {e}")
                return "xml", None


def validate_bom_file(file_path: str):
    """
    Perform Level 3 validation: structural + schema compliance.
    """
    if not os.path.exists(file_path):
        console.print(f"[red]❌ File not found:[/red] {file_path}")
        return False

    format_type, spec_version = detect_bom_format_and_version(file_path)
    if not spec_version:
        console.print("[red]❌ specVersion not found in BOM.[/red]")
        return False

    console.print(f"[cyan]Detected format:[/cyan] {format_type.upper()}  [cyan]Version:[/cyan] {spec_version}")

    schema_path = ensure_schema_exists(format_type, spec_version)
    if not schema_path:
        console.print("[yellow]⚠️ Schema not available for validation. Skipping strict check.[/yellow]")
        return True  # fallback to soft validation

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

        console.print(f"[green]✅ BOM is valid according to CycloneDX {spec_version} schema![/green]")
        return True

    except ValidationError as e:
        console.print(f"[red]❌ JSON Schema validation failed:[/red] {e.message}")
        return False
    except etree.DocumentInvalid as e:
        console.print(f"[red]❌ XML Schema validation failed:[/red] {e}")
        return False
    except Exception as e:
        console.print(f"[red]⚠️ Unexpected error during validation:[/red] {e}")
        return False
