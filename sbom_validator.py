# sbom_validator.py
import json
from dataclasses import dataclass
from lxml import etree
from utils.file_utils import validate_file_path

# IMPORTANT: this import expects validator/ to be a package (validator/__init__.py present)
from validator.schema_validator import validate_against_schema

@dataclass
class BOMDetectionResult:
    file_ok: bool = False
    parse_ok: bool = False
    format: str | None = None         # json / xml
    bom_type: str | None = None       # cyclonedx / spdx / unknown
    spec_version: str | None = None
    errors: list = None

    # Phase2 schema results
    phase2_schema_ok: bool | None = None
    phase2_schema_errors: list | None = None

    # parsed payload for later phases
    parsed: object | None = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.phase2_schema_errors is None:
            self.phase2_schema_errors = []


class SBOMPhase1Validator:

    def __init__(self, path: str):
        self.path = path
        self.result = BOMDetectionResult()
        self.parsed = None

    def check_file(self):
        ok, err = validate_file_path(self.path)
        self.result.file_ok = ok
        if not ok:
            self.result.errors.append(err)
            return False
        return True

    def detect_format(self):
        if self.path.lower().endswith(".json"):
            self.result.format = "json"
        elif self.path.lower().endswith(".xml"):
            self.result.format = "xml"
        else:
            self.result.format = None
            self.result.errors.append("Unsupported file extension. Only .json and .xml are allowed.")
        return self.result.format

    def parse_file(self):
        if self.result.format == "json":
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self.parsed = json.load(f)
                self.result.parse_ok = True
                self.result.parsed = self.parsed
            except Exception as e:
                self.result.errors.append(f"JSON parse error: {e}")
                self.result.parse_ok = False

        elif self.result.format == "xml":
            try:
                parser = etree.XMLParser(resolve_entities=False, no_network=True)
                self.parsed = etree.parse(self.path, parser)
                self.result.parse_ok = True
                self.result.parsed = self.parsed
            except Exception as e:
                self.result.errors.append(f"XML parse error: {e}")
                self.result.parse_ok = False

        return self.result.parse_ok

    def detect_bom_type(self):
        if not self.result.parse_ok:
            return None

        # JSON
        if self.result.format == "json" and isinstance(self.parsed, dict):
            if self.parsed.get("bomFormat", "").lower() == "cyclonedx":
                self.result.bom_type = "cyclonedx"
                self.result.spec_version = self.parsed.get("specVersion")
                return "cyclonedx"
            if "spdxVersion" in self.parsed:
                self.result.bom_type = "spdx"
                self.result.spec_version = self.parsed.get("spdxVersion")
                return "spdx"

        # XML
        if self.result.format == "xml":
            try:
                root = self.parsed.getroot()
                ns = root.nsmap.get(None, "") if isinstance(root, etree._Element) else ""
            except Exception:
                self.result.errors.append("Could not read XML namespace from root.")
                return None

            if "cyclonedx.org/schema/bom" in ns:
                self.result.bom_type = "cyclonedx"
                # last path segment is version
                try:
                    self.result.spec_version = ns.split("/")[-1]
                except Exception:
                    self.result.spec_version = root.get("version")
                return "cyclonedx"

            if "spdx" in ns or root.tag.lower().endswith("spdx"):
                self.result.bom_type = "spdx"
                self.result.spec_version = root.get("version")
                return "spdx"

        self.result.bom_type = "unknown"
        self.result.errors.append("Could not detect SBOM type (CycloneDX or SPDX).")
        return None

    def run_schema_validation(self):
        ok, msg = validate_against_schema(self.path, auto_download=True)
        self.result.phase2_schema_ok = ok
        if isinstance(msg, list):
            self.result.phase2_schema_errors.extend(msg)
        else:
            self.result.phase2_schema_errors.append(msg)

    def run(self) -> BOMDetectionResult:
        # Phase 1
        if not self.check_file():
            return self.result

        self.detect_format()
        if not self.result.format:
            return self.result

        self.parse_file()
        if not self.result.parse_ok:
            return self.result

        self.detect_bom_type()

        # Phase 2 (schema) - only if we have type + version
        if self.result.bom_type and self.result.spec_version:
            self.run_schema_validation()

        return self.result


# wrapper for main.py
def validate_bom_file(path: str) -> BOMDetectionResult:
    v = SBOMPhase1Validator(path)
    return v.run()
