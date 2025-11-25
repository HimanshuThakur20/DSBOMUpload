# validator/semantic_validator.py
"""
Optimized, modular, auto-registering semantic SBOM validator.
Supports CycloneDX + SPDX for JSON & XML.
"""

import re
from typing import Any, Dict, List, Callable
from packaging.version import Version, InvalidVersion
from lxml import etree

# SPDX license id heuristic
SPDX_ID_PATTERN = re.compile(r"^[A-Za-z0-9\.\-\+:]+$")

# ======================================================================
# CHECK REGISTRATION
# ======================================================================

CHECK_REGISTRY: Dict[str, Callable] = {}

def sbom_check(name: str):
    """Decorator to auto-register a semantic validation check."""
    def wrapper(func):
        CHECK_REGISTRY[name] = func
        return func
    return wrapper

# ======================================================================
# HELPERS — UNIFIED ACCESS LAYER
# ======================================================================

def is_json(parsed) -> bool:
    return isinstance(parsed, dict)

def get_root(parsed):
    return parsed.getroot() if hasattr(parsed, "getroot") else None

def get_ns(root):
    return root.nsmap.get(None, "") if root is not None else ""

def get_xml_list(root, tag):
    ns = get_ns(root)
    if ns:
        return root.findall(f".//{{{ns}}}{tag}")
    return root.findall(f".//{tag}")

def xml_child_text(elem, name: str):
    """Return text of first child matching tag ending with name."""
    for child in elem:
        if isinstance(child.tag, str) and child.tag.endswith(name):
            return (child.text or "").strip()
    return None

# ======================================================================
# SBOM COMPONENT/PACKAGE EXTRACTORS
# ======================================================================

def get_components(parsed, fmt, bom_type):
    """Unified component/package extractor."""
    if bom_type == "spdx":
        return get_spdx_packages(parsed, fmt)
    return get_cyclonedx_components(parsed, fmt)

def get_cyclonedx_components(parsed, fmt):
    if fmt == "json":
        return parsed.get("components", []) or []
    root = get_root(parsed)
    return get_xml_list(root, "component")

def get_spdx_packages(parsed, fmt):
    if fmt == "json":
        return parsed.get("packages", []) or []
    root = get_root(parsed)
    return get_xml_list(root, "Package")

# ======================================================================
# COMMON CHECK UTIL
# ======================================================================

def check_missing(parsed_list, extract_fn) -> (bool, List):
    """Generic helper for required-field checks."""
    missing = []
    for elem in parsed_list:
        value = extract_fn(elem)
        if not value:
            missing.append(elem)
    return (len(missing) == 0, missing)

# ======================================================================
# REGISTERED CHECKS
# ======================================================================

# ----------------------------------------------------------------------
@sbom_check("require_component_name")
def require_component_name(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)

    def extract(item):
        if fmt == "json":
            return item.get("name")
        return xml_child_text(item, "name")

    ok, missing = check_missing(items, extract)
    return {
        "passed": ok,
        "message": f"{len(missing)}/{len(items)} missing component name",
        "details": missing,
    }

# ======================================================================
# 🔥 FULLY REWRITTEN VERSION CHECK (SPEC + REAL-WORLD + FUTURE-PROOF)
# ======================================================================

REQUIRES_VERSION_TYPES = {
    "library",
    "framework",
    "application",
    "container",
    "operating-system",
}

FLOATING_VERSION_MARKERS = {
    "latest", "master", "main", "head", "dev", "develop", "*"
}


def normalize_purl_version(purl: str | None):
    if not purl or '@' not in purl:
        return None

    ver = purl.split('@', 1)[1]
    if '?' in ver:
        ver = ver.split('?', 1)[0]
    return ver.strip() or None


def cyclonedx_extract_type(item, fmt):
    if fmt == "json":
        return (item.get("type") or "").lower()
    return xml_child_text(item, "type") or ""


def cyclonedx_extract_version(item, fmt):
    return item.get("version") if fmt == "json" else xml_child_text(item, "version")


def cyclonedx_extract_purl(item, fmt):
    return item.get("purl") if fmt == "json" else xml_child_text(item, "purl")


@sbom_check("require_component_version")
def require_component_version(parsed, fmt, bom_type):
    """
    Robust, spec-aligned version-required logic.
    """
    items = get_components(parsed, fmt, bom_type)

    # SPDX handles version differently → skip required version enforcement
    if bom_type == "spdx":
        return {
            "passed": True,
            "message": "SPDX version rule not enforced here",
            "details": None,
        }

    missing = []
    total = len(items)

    for item in items:
        # 1. extract
        ctype = cyclonedx_extract_type(item, fmt)
        version = cyclonedx_extract_version(item, fmt)
        purl = cyclonedx_extract_purl(item, fmt)

        # 2. bom-ref or placeholder for reporting
        cref = item.get("bom-ref") if fmt == "json" else "<xml_component>"
        cref = str(cref)

        # 3. skip synthetic
        if cref.startswith(("urn:uuid:", "internal:", "file:", "sha256:", "docker:")):
            continue

        # 4. version not required for these types
        requires_version = ctype in REQUIRES_VERSION_TYPES

        # 5. if version exists → PASS
        if version:
            continue

        # 6. if PURL embeds a usable version → PASS
        purl_ver = normalize_purl_version(purl)
        if purl_ver:
            if purl_ver.lower() in FLOATING_VERSION_MARKERS:
                continue
            else:
                continue  # concrete version → PASS

        # 7. no version + required → FAIL
        if requires_version:
            missing.append(cref)

    passed = len(missing) == 0
    msg = f"{len(missing)}/{total} components missing required version"

    return {
        "passed": passed,
        "message": msg,
        "details": missing,
    }

# ----------------------------------------------------------------------
@sbom_check("require_description")
def require_description(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)

    def extract(item):
        return item.get("description") if fmt == "json" else xml_child_text(item, "description")

    ok, missing = check_missing(items, extract)
    return {
        "passed": ok,
        "message": f"{len(missing)}/{len(items)} missing description",
        "details": missing,
    }

# ----------------------------------------------------------------------
@sbom_check("require_license")
def require_license(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)

    def extract(item):
        if fmt == "json":
            if bom_type == "spdx":
                return item.get("licenseConcluded") or item.get("licenseDeclared")
            return item.get("licenses")
        return xml_child_text(item, "license") or xml_child_text(item, "licenseDeclared")

    ok, missing = check_missing(items, extract)
    return {
        "passed": ok,
        "message": f"{len(missing)}/{len(items)} missing license",
        "details": missing,
    }

# ----------------------------------------------------------------------
@sbom_check("require_supplier")
def require_supplier(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)

    def extract(item):
        return (
            item.get("supplier") or item.get("PackageSupplier")
            if fmt == "json" else
            xml_child_text(item, "supplier") or xml_child_text(item, "PackageSupplier")
        )

    ok, missing = check_missing(items, extract)
    return {
        "passed": ok,
        "message": f"{len(missing)}/{len(items)} missing supplier",
        "details": missing,
    }

# ----------------------------------------------------------------------
@sbom_check("require_purl")
def require_purl(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)

    def extract(item):
        return (
            item.get("purl") or item.get("PackageDownloadLocation")
            if fmt == "json" else
            xml_child_text(item, "purl") or xml_child_text(item, "PackageDownloadLocation")
        )

    ok, missing = check_missing(items, extract)
    return {
        "passed": ok,
        "message": f"{len(missing)}/{len(items)} missing purl",
        "details": missing,
    }

# ----------------------------------------------------------------------
@sbom_check("require_dependencies")
def require_dependencies(parsed, fmt, bom_type):
    if bom_type == "cyclonedx":
        present = bool(parsed.get("dependencies")) if fmt == "json" else \
                  bool(get_xml_list(get_root(parsed), "dependencies"))
    else:
        present = any(
            r.get("relationshipType") == "DEPENDS_ON"
            for r in (parsed.get("relationships") or [])
        ) if fmt == "json" else \
        bool(get_xml_list(get_root(parsed), "relationship"))

    return {
        "passed": present,
        "message": "Dependencies present" if present else "Dependencies missing",
        "details": None,
    }

# ----------------------------------------------------------------------
@sbom_check("require_author")
def require_author(parsed, fmt, bom_type):
    if bom_type == "cyclonedx":
        if fmt == "json":
            authors = parsed.get("metadata", {}).get("authors") or []
            return {"passed": bool(authors),
                    "message": "Authors present" if authors else "No authors",
                    "details": authors}
        authors = get_xml_list(get_root(parsed), "author")
        return {"passed": bool(authors),
                "message": "Authors present" if authors else "No authors",
                "details": authors}

    # SPDX
    if fmt == "json":
        creators = parsed.get("creator") or parsed.get("creators") or []
        return {"passed": bool(creators),
                "message": "Creators present" if creators else "No creators",
                "details": creators}

    created = xml_child_text(get_root(parsed), "creator")
    return {
        "passed": bool(created),
        "message": "Creator present" if created else "No creator",
        "details": created,
    }

# ----------------------------------------------------------------------
@sbom_check("require_timestamp")
def require_timestamp(parsed, fmt, bom_type):
    ts = (
        parsed.get("metadata", {}).get("timestamp")
        if fmt == "json" else
        xml_child_text(get_root(parsed), "timestamp")
    ) if bom_type == "cyclonedx" else \
         (parsed.get("created") if fmt == "json" else
          xml_child_text(get_root(parsed), "created"))

    return {"passed": bool(ts),
            "message": "Timestamp present" if ts else "No timestamp",
            "details": ts}

# ----------------------------------------------------------------------
@sbom_check("validate_version_semver")
def validate_version_semver(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)
    bad = []
    for item in items:
        ver = item.get("version") if fmt == "json" else xml_child_text(item, "version")
        if ver:
            try:
                Version(ver)
            except InvalidVersion:
                bad.append((item, ver))
    return {
        "passed": len(bad) == 0,
        "message": f"{len(bad)}/{len(items)} non-semver versions",
        "details": bad,
    }

# ----------------------------------------------------------------------
@sbom_check("validate_spdx_license_id")
def validate_spdx_license_id(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)
    bad = []
    for item in items:
        if fmt == "json":
            lid = item.get("licenseDeclared") or item.get("licenseConcluded")
        else:
            lid = xml_child_text(item, "licenseDeclared")
        if not lid:
            continue

        for token in re.split(r"[ \t()]+", lid):
            t = token.strip()
            if not t or t.upper() in ("AND", "OR", "WITH"):
                continue
            if not SPDX_ID_PATTERN.match(t):
                bad.append((item, lid))
                break

    return {
        "passed": len(bad) == 0,
        "message": f"{len(bad)}/{len(items)} invalid SPDX identifiers",
        "details": bad,
    }

# ======================================================================
# PUBLIC DISPATCHER
# ======================================================================

def run_semantic_checks(parsed, fmt, bom_type, spec_version=None) -> Dict[str, Dict]:
    """
    Automatically runs all registered semantic checks.
    """
    results = {}
    for name, func in CHECK_REGISTRY.items():
        try:
            results[name] = func(parsed, fmt, bom_type)
        except Exception as ex:
            results[name] = {
                "passed": False,
                "message": f"Check crashed: {ex}",
                "details": None,
            }
    return results

# ======================================================================
# NTIA / BOM STRUCTURE CHECKS (NEW)
# ======================================================================

@sbom_check("require_bom_format")
def require_bom_format(parsed, fmt, bom_type):
    if fmt == "json":
        ok = bool(parsed.get("bomFormat"))
        return {
            "passed": ok,
            "message": "bomFormat present" if ok else "Missing bomFormat",
            "details": parsed.get("bomFormat"),
        }
    # XML always has bomFormat implied; consider present
    return {"passed": True, "message": "bomFormat implicit in XML", "details": None}


@sbom_check("require_spec_version")
def require_spec_version(parsed, fmt, bom_type):
    if fmt == "json":
        ver = parsed.get("specVersion")
        return {
            "passed": bool(ver),
            "message": "specVersion present" if ver else "Missing specVersion",
            "details": ver,
        }
    # XML: attribute on <bom>
    root = get_root(parsed)
    ver = root.attrib.get("version") if root is not None else None
    return {
        "passed": bool(ver),
        "message": "specVersion present" if ver else "Missing specVersion",
        "details": ver,
    }


@sbom_check("require_metadata_section")
def require_metadata_section(parsed, fmt, bom_type):
    if fmt == "json":
        meta = parsed.get("metadata")
        ok = isinstance(meta, dict)
        return {
            "passed": ok,
            "message": "Metadata section present" if ok else "Missing metadata section",
            "details": meta,
        }

    root = get_root(parsed)
    meta = get_xml_list(root, "metadata")
    ok = bool(meta)
    return {
        "passed": ok,
        "message": "Metadata section present" if ok else "Missing metadata section",
        "details": meta,
    }


@sbom_check("require_root_component")
def require_root_component(parsed, fmt, bom_type):
    if fmt == "json":
        root_cmp = parsed.get("metadata", {}).get("component")
        ok = isinstance(root_cmp, dict)
        return {
            "passed": ok,
            "message": "Root component present" if ok else "Missing root component",
            "details": root_cmp,
        }

    root_elem = get_xml_list(get_root(parsed), "component")
    ok = bool(root_elem)
    return {
        "passed": ok,
        "message": "Root component present" if ok else "Missing root component",
        "details": root_elem,
    }


@sbom_check("require_root_component_name")
def require_root_component_name(parsed, fmt, bom_type):
    if fmt == "json":
        cmp = parsed.get("metadata", {}).get("component", {})
        name = cmp.get("name")
        return {
            "passed": bool(name),
            "message": "Root component name present" if name else "Missing root component name",
            "details": name,
        }

    # XML
    meta = get_xml_list(get_root(parsed), "metadata")
    if not meta:
        return {"passed": False, "message": "Missing metadata", "details": None}

    name = xml_child_text(meta[0], "name")
    return {
        "passed": bool(name),
        "message": "Root component name present" if name else "Missing root component name",
        "details": name,
    }


@sbom_check("require_root_component_ref")
def require_root_component_ref(parsed, fmt, bom_type):
    if fmt == "json":
        cmp = parsed.get("metadata", {}).get("component", {})
        bref = cmp.get("bom-ref")
        return {
            "passed": bool(bref),
            "message": "Root component bom-ref present" if bref else "Missing root component bom-ref",
            "details": bref,
        }

    meta = get_xml_list(get_root(parsed), "metadata")
    if not meta:
        return {"passed": False, "message": "Missing metadata", "details": None}

    # attribute on <component>
    comp_elem = meta[0].find(".//*")
    bref = comp_elem.attrib.get("bom-ref") if comp_elem is not None else None
    return {
        "passed": bool(bref),
        "message": "Root component bom-ref present" if bref else "Missing root component bom-ref",
        "details": bref,
    }


# ======================================================================
# IDENTIFIER RULE — purl OR cpe must be present
# ======================================================================

@sbom_check("require_cpe_or_purl")
def require_cpe_or_purl(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)
    missing = []

    for item in items:
        if fmt == "json":
            purl = item.get("purl")
            cpe = item.get("cpe")
        else:
            purl = xml_child_text(item, "purl")
            cpe = xml_child_text(item, "cpe")

        if not purl and not cpe:
            missing.append(item)

    return {
        "passed": len(missing) == 0,
        "message": f"{len(missing)}/{len(items)} missing identifier (purl or cpe)",
        "details": missing,
    }
