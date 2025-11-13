# validator.py

import json
from dataclasses import dataclass
from lxml import etree
from utils.file_utils import validate_file_path

# ⬇ NEW: schema validator import
from validator.schema_validator import validate_against_schema


@dataclass
class BOMDetectionResult:
    file_ok: bool = False
    parse_ok: bool = False
    format: str | None = None         # json / xml
    bom_type: str | None = None       # cyclonedx / spdx / unknown
    spec_version: str | None = None
    errors: list = None

    # NEW FIELDS FOR PHASE-2
    phase2_schema_ok: bool = None
    phase2_errors: list = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.phase2_errors is None:
            self.phase2_errors = []


class SBOMPhase1Validator:

    def __init__(self, path: str):
        self.path = path
        self.result = BOMDetectionResult()
        self.parsed = None

    # ------------------------------------------------------------------
    # 1. Validate file path
    # ------------------------------------------------------------------
    def check_file(self):
        ok, err = validate_file_path(self.path)
        self.result.file_ok = ok

        if not ok:
            self.result.errors.append(err)
            return False

        return True

    # ------------------------------------------------------------------
    # 2. Detect file format (.json / .xml)
    # ------------------------------------------------------------------
    def detect_format(self):
        if self.path.lower().endswith(".json"):
            self.result.format = "json"

        elif self.path.lower().endswith(".xml"):
            self.result.format = "xml"

        else:
            self.result.format = None
            self.result.errors.append(
                "Unsupported file extension. Only .json and .xml are allowed."
            )

        return self.result.format

    # ------------------------------------------------------------------
    # 3. Parse JSON or XML using safe methods
    # ------------------------------------------------------------------
    def parse_file(self):
        if self.result.format == "json":
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self.parsed = json.load(f)
                self.result.parse_ok = True

            except Exception as e:
                self.result.errors.append(f"JSON parse error: {str(e)}")

        elif self.result.format == "xml":
            try:
                parser = etree.XMLParser(resolve_entities=False, no_network=True)
                self.parsed = etree.parse(self.path, parser)
                self.result.parse_ok = True

            except Exception as e:
                self.result.errors.append(f"XML parse error: {str(e)}")

        return self.result.parse_ok

    # ------------------------------------------------------------------
    # 4. Detect BOM type (CycloneDX / SPDX)
    # ------------------------------------------------------------------
    def detect_bom_type(self):
        if not self.result.parse_ok:
            return None

        # -----------------------
        # JSON detection
        # -----------------------
        if self.result.format == "json" and isinstance(self.parsed, dict):

            # CycloneDX JSON
            if self.parsed.get("bomFormat", "").lower() == "cyclonedx":
                self.result.bom_type = "cyclonedx"
                self.result.spec_version = self.parsed.get("specVersion")
                return "cyclonedx"

            # SPDX JSON
            if "spdxVersion" in self.parsed:
                self.result.bom_type = "spdx"
                self.result.spec_version = self.parsed.get("spdxVersion")
                return "spdx"

        # -----------------------
        # XML detection
        # -----------------------
        if self.result.format == "xml":
            try:
                root = self.parsed.getroot()
                ns = root.nsmap.get(None, "")  # default namespace
            except Exception:
                self.result.errors.append("Could not read XML namespace from root.")
                return None

            # CycloneDX XML
            if "cyclonedx" in ns or "bom" in ns:
                self.result.bom_type = "cyclonedx"
                version = ns.split("/")[-1]
                self.result.spec_version = version
                return "cyclonedx"

            # SPDX XML
            if "spdx" in ns:
                self.result.bom_type = "spdx"
                self.result.spec_version = root.get("version")
                return "spdx"

        # Unknown BOM type
        self.result.bom_type = "unknown"
        self.result.errors.append(
            "Could not detect SBOM type. Neither CycloneDX nor SPDX signatures found."
        )
        return None

    # ------------------------------------------------------------------
    # **5. Run Phase 2: Schema validation**
    # ------------------------------------------------------------------
    def run_schema_validation(self):
        """
        Calls the dynamic schema validator.
        Saves result into phase2_schema_ok + phase2_errors.
        """
        ok, msg = validate_against_schema(self.path)

        self.result.phase2_schema_ok = ok

        # force msg into list
        if isinstance(msg, list):
            self.result.phase2_errors.extend(msg)
        else:
            self.result.phase2_errors.append(msg)

    # ------------------------------------------------------------------
    # 6. Run Phase 1 + Phase 2
    # ------------------------------------------------------------------
    def run(self) -> BOMDetectionResult:
        """
        Executes Phase 1 workflow,
        then runs Phase 2 schema validation if Phase 1 is clean.
        """

        # -----------------------
        # Phase 1
        # -----------------------
        if not self.check_file():
            return self.result

        self.detect_format()
        if not self.result.format:
            return self.result

        self.parse_file()
        if not self.result.parse_ok:
            return self.result

        self.detect_bom_type()

        # -----------------------
        # Phase 2 (Schema validation)
        # Only run if Phase 1 passed
        # -----------------------
        if self.result.bom_type and self.result.spec_version:
            self.run_schema_validation()

        return self.result


# -------- Helper Function for main.py -------- #

def validate_bom_file(path: str) -> BOMDetectionResult:
    validator = SBOMPhase1Validator(path)
    return validator.run()
