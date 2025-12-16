"""
Semantic SBOM Validator (CycloneDX + SPDX)
Implements all rules listed in updated policy.yaml.
Optional fields (Origin, EOL, Usage Restrictions, etc.)
generate WARN when missing (Option B).
"""

import re
from typing import Any, Dict, List, Callable
from packaging.version import Version, InvalidVersion
from lxml import etree

CHECK_REGISTRY: Dict[str, Callable] = {}

def sbom_check(name: str):
    """Decorator to auto-register semantic validation checks."""
    def wrapper(func):
        CHECK_REGISTRY[name] = func
        return func
    return wrapper

# ---------------------------
# Helpers
# ---------------------------

def is_json(parsed) -> bool:
    return isinstance(parsed, dict)

def get_root(parsed):
    return parsed.getroot() if hasattr(parsed, "getroot") else None

def get_ns(root):
    return root.nsmap.get(None, "") if root is not None else ""

def get_xml_list(root, tag):
    ns = get_ns(root)
    return root.findall(f".//{{{ns}}}{tag}") if ns else root.findall(f".//{tag}")

def xml_child_text(elem, name: str):
    if elem is None:
        return None
    for ch in elem:
        if isinstance(ch.tag, str) and ch.tag.endswith(name):
            return (ch.text or "").strip()
    return None

# ---------------------------
# Component extractors
# ---------------------------

def get_components(parsed, fmt, bom_type):
    if bom_type == "spdx":
        if fmt == "json":
            return parsed.get("packages", []) or []
        return get_xml_list(get_root(parsed), "Package")

    # CycloneDX
    if fmt == "json":
        return parsed.get("components", []) or []
    return get_xml_list(get_root(parsed), "component")


# ---------------------------
# Generic missing checker
# ---------------------------

def check_missing(parsed_list, extract_fn):
    missing = []
    for item in parsed_list:
        if not extract_fn(item):
            missing.append(item)
    return (len(missing) == 0, missing)


# ============================================================
# REQUIRED FIELDS
# ============================================================

@sbom_check("require_component_name")
def require_component_name(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)
    def extract(x):
        return x.get("name") if fmt == "json" else xml_child_text(x, "name")
    ok, missing = check_missing(items, extract)
    return {
        "passed": ok,
        "message": f"{len(missing)}/{len(items)} missing component name",
        "details": missing,
    }


# ---------------------------
# Component Version Required
# ---------------------------

VERSION_TYPES_REQUIRING_VERSION = {
    "library", "framework", "application", "container", "operating-system"
}

VERSION_FLOATING_MARKERS = {"latest", "main", "master", "dev", "head", "*"}

def extract_version(item, fmt):
    return item.get("version") if fmt == "json" else xml_child_text(item, "version")

def extract_type(item, fmt):
    return (item.get("type") or "").lower() if fmt == "json" else xml_child_text(item, "type") or ""

def extract_purl(item, fmt):
    return item.get("purl") if fmt == "json" else xml_child_text(item, "purl")

def purl_version(purl: str | None):
    if not purl or "@" not in purl:
        return None
    v = purl.split("@")[1].split("?")[0]
    return v.strip() or None

@sbom_check("require_component_version")
def require_component_version(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)

    missing = []
    for item in items:
        ctype = extract_type(item, fmt)
        version = extract_version(item, fmt)
        p = extract_purl(item, fmt)

        # If version exists → OK
        if version:
            continue

        # PURL version fallback
        pv = purl_version(p)
        if pv and pv.lower() not in VERSION_FLOATING_MARKERS:
            continue

        # Required type?
        if ctype in VERSION_TYPES_REQUIRING_VERSION:
            missing.append(item)

    passed = len(missing) == 0
    return {
        "passed": passed,
        "message": f"{len(missing)}/{len(items)} components missing required version",
        "details": missing,
    }


# ---------------------------
# Component Description Required (STRICT)
# ---------------------------

@sbom_check("require_description")
def require_description(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)

    def extract(x):
        return x.get("description") if fmt == "json" else xml_child_text(x, "description")

    ok, missing = check_missing(items, extract)
    return {
        "passed": ok,
        "message": f"{len(missing)}/{len(items)} missing description",
        "details": missing,
    }


# ---------------------------
# Component License Required
# ---------------------------

@sbom_check("require_license")
def require_license(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)

    def extract(x):
        if fmt == "json":
            return x.get("licenses")
        return xml_child_text(x, "license")

    ok, missing = check_missing(items, extract)
    return {
        "passed": ok,
        "message": f"{len(missing)}/{len(items)} missing license",
        "details": missing,
    }


# ---------------------------
# Supplier Required
# ---------------------------

@sbom_check("require_supplier")
def require_supplier(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)
    def extract(x):
        return x.get("supplier") if fmt == "json" else xml_child_text(x, "supplier")
    ok, missing = check_missing(items, extract)
    return {
        "passed": ok,
        "message": f"{len(missing)}/{len(items)} missing supplier",
        "details": missing,
    }


# ---------------------------
# PURL required
# ---------------------------

@sbom_check("require_purl")
def require_purl(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)
    def extract(x):
        return x.get("purl") if fmt == "json" else xml_child_text(x, "purl")
    ok, missing = check_missing(items, extract)
    return {
        "passed": ok,
        "message": f"{len(missing)}/{len(items)} missing purl",
        "details": missing,
    }


# ============================================================
# OPTIONAL COMPONENT METADATA (B → WARN)
# ============================================================

def optional_field_check(items, fmt, field, xml_field=None):
    missing = []

    for item in items:
        if fmt == "json":
            val = item.get(field)
        else:
            val = xml_child_text(item, xml_field or field)

        if not val:
            missing.append(item)

    return {
        "passed": len(missing) == 0,
        "message": f"{len(missing)}/{len(items)} missing {field}",
        "details": missing,
    }

@sbom_check("component_origin")
def component_origin(parsed, fmt, bom_type):
    return optional_field_check(get_components(parsed, fmt, bom_type), fmt, "origin")


@sbom_check("release_date")
def release_date(parsed, fmt, bom_type):
    return optional_field_check(get_components(parsed, fmt, bom_type), fmt, "releaseDate")


@sbom_check("eol_date")
def eol_date(parsed, fmt, bom_type):
    return optional_field_check(get_components(parsed, fmt, bom_type), fmt, "eol")


@sbom_check("usage_restrictions")
def usage_restrictions(parsed, fmt, bom_type):
    return optional_field_check(get_components(parsed, fmt, bom_type), fmt, "usageRestrictions")


@sbom_check("comments_notes")
def comments_notes(parsed, fmt, bom_type):
    return optional_field_check(get_components(parsed, fmt, bom_type), fmt, "comments")


# ============================================================
# IDENTIFIER CHECK
# ============================================================

@sbom_check("require_cpe_or_purl")
def require_cpe_or_purl(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)
    missing = []
    for item in items:
        purl = item.get("purl") if fmt == "json" else xml_child_text(item, "purl")
        cpe = item.get("cpe") if fmt == "json" else xml_child_text(item, "cpe")
        if not purl and not cpe:
            missing.append(item)
    return {
        "passed": len(missing) == 0,
        "message": f"{len(missing)}/{len(items)} missing identifier (purl or cpe)",
        "details": missing,
    }


# ============================================================
# LICENSE VALIDATION (warning)
# ============================================================

SPDX_ID_PATTERN = re.compile(r"^[A-Za-z0-9\.\-\+:]+$")

@sbom_check("validate_spdx_license_id")
def validate_spdx_license_id(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)
    bad = []

    for item in items:
        if fmt == "json":
            lid = item.get("licenseDeclared")
        else:
            lid = xml_child_text(item, "licenseDeclared")

        if not lid:
            continue

        for token in re.split(r"[ \t()]+", lid):
            if token.upper() in ("AND", "OR", "WITH"):
                continue
            if not SPDX_ID_PATTERN.match(token):
                bad.append((item, lid))
                break

    return {
        "passed": len(bad) == 0,
        "message": f"{len(bad)}/{len(items)} invalid SPDX identifiers",
        "details": bad,
    }


# ============================================================
# SEMVER VERSION VALIDATOR (warning)
# ============================================================

@sbom_check("validate_version_semver")
def validate_version_semver(parsed, fmt, bom_type):
    items = get_components(parsed, fmt, bom_type)
    bad = []
    for item in items:
        ver = item.get("version") if fmt == "json" else xml_child_text(item, "version")
        if not ver:
            continue
        try:
            Version(ver)
        except InvalidVersion:
            bad.append((item, ver))

    return {
        "passed": len(bad) == 0,
        "message": f"{len(bad)}/{len(items)} non-semver versions",
        "details": bad,
    }


# ============================================================
# METADATA + ROOT COMPONENT
# ============================================================

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

    meta = get_xml_list(get_root(parsed), "metadata")
    return {
        "passed": bool(meta),
        "message": "Metadata section present" if meta else "Missing metadata section",
        "details": meta,
    }


@sbom_check("require_root_component")
def require_root_component(parsed, fmt, bom_type):
    if fmt == "json":
        cmp = parsed.get("metadata", {}).get("component")
        return {
            "passed": isinstance(cmp, dict),
            "message": "Root component present" if cmp else "Missing root component",
            "details": cmp,
        }

    elems = get_xml_list(get_root(parsed), "component")
    return {
        "passed": bool(elems),
        "message": "Root component present" if elems else "Missing root component",
        "details": elems,
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

    cmp_elem = meta[0].find(".//*")
    bref = cmp_elem.attrib.get("bom-ref") if cmp_elem is not None else None
    return {
        "passed": bool(bref),
        "message": "Root component bom-ref present" if bref else "Missing root component bom-ref",
        "details": bref,
    }


# ============================================================
# TIMESTAMP + AUTHOR
# ============================================================

@sbom_check("require_author")
def require_author(parsed, fmt, bom_type):
    if fmt == "json":
        authors = parsed.get("metadata", {}).get("authors") or []
        return {
            "passed": bool(authors),
            "message": "Authors present" if authors else "No authors",
            "details": authors,
        }

    # XML
    authors = get_xml_list(get_root(parsed), "author")
    return {
        "passed": bool(authors),
        "message": "Authors present" if authors else "No authors",
        "details": authors,
    }


@sbom_check("require_timestamp")
def require_timestamp(parsed, fmt, bom_type):
    if fmt == "json":
        ts = parsed.get("metadata", {}).get("timestamp")
    else:
        ts = xml_child_text(get_root(parsed), "timestamp")

    return {
        "passed": bool(ts),
        "message": "Timestamp present" if ts else "No timestamp",
        "details": ts,
    }


# ============================================================
# DEPENDENCIES
# ============================================================

@sbom_check("require_dependencies")
def require_dependencies(parsed, fmt, bom_type):
    if fmt == "json":
        deps = parsed.get("dependencies")
        ok = bool(deps)
    else:
        ok = bool(get_xml_list(get_root(parsed), "dependency"))

    return {
        "passed": ok,
        "message": "Dependencies present" if ok else "Dependencies missing",
        "details": None,
    }


# ============================================================
# Public dispatcher
# ============================================================

def run_semantic_checks(parsed, fmt, bom_type, spec_version=None) -> Dict[str, Dict]:
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
