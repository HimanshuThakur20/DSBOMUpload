import os
import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, List

from config import get_automation_root
from project import get_or_create_project, get_latest_version
from bom import upload_bom


VALID_SBOM_DIR = "Valid SBOM"
OUTPUT_DIR = "Output"
LOG_DIR = "logs"

REGISTRY_FILE = "upload_registry.json"
SUMMARY_FILE = "upload_summary.json"

SUPPORTED_EXTENSIONS = (".json", ".xml")


# ==========================================================
# HELPERS
# ==========================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: str, default):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default


def save_json(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def bump_version(ver: str) -> str:
    parts = ver.split(".")
    if len(parts) == 1:
        return f"{parts[0]}.1"
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


def setup_logger(app_path: str) -> logging.Logger:
    log_dir = os.path.join(app_path, LOG_DIR)
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger(app_path)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.FileHandler(
            os.path.join(log_dir, "upload.log"),
            encoding="utf-8"
        )
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


# ==========================================================
# CORE AUTOMATION
# ==========================================================

def process_application(app_path: str):
    app_name = os.path.basename(app_path)

    valid_dir = os.path.join(app_path, VALID_SBOM_DIR)
    output_dir = os.path.join(app_path, OUTPUT_DIR)

    if not os.path.isdir(valid_dir):
        return

    os.makedirs(output_dir, exist_ok=True)

    logger = setup_logger(app_path)
    logger.info(f"Starting SBOM automation for application: {app_name}")

    registry_path = os.path.join(output_dir, REGISTRY_FILE)
    summary_path = os.path.join(output_dir, SUMMARY_FILE)

    registry: Dict = load_json(
        registry_path,
        {"application": app_name, "uploads": {}}
    )

    run_summary = {
        "run_at": utc_now(),
        "application": app_name,
        "results": []
    }

    # ------------------------------------------------------
    # Discover SBOMs
    # ------------------------------------------------------
    sbom_files: List[str] = [
        os.path.join(valid_dir, f)
        for f in os.listdir(valid_dir)
        if f.lower().endswith(SUPPORTED_EXTENSIONS)
    ]

    sbom_files.sort(key=lambda p: os.path.getmtime(p))

    logger.info(f"Found {len(sbom_files)} SBOM(s) to process")

    # ------------------------------------------------------
    # Upload flow
    # ------------------------------------------------------
    current_version = get_latest_version(app_name)

    for sbom_path in sbom_files:
        sbom_name = os.path.basename(sbom_path)
        sbom_hash = sha256_file(sbom_path)

        # Deduplication
        if sbom_hash in registry["uploads"]:
            logger.info(f"Skipping already uploaded SBOM: {sbom_name}")
            run_summary["results"].append({
                "file": sbom_name,
                "status": "SKIPPED",
                "reason": "Already uploaded",
                "hash": sbom_hash
            })
            continue

        # Version calculation
        version = "1.0" if current_version is None else bump_version(current_version)

        logger.info(f"Processing SBOM={sbom_name} version={version}")

        project = get_or_create_project(app_name, version)
        if not project:
            logger.error(f"Project creation failed for {app_name} {version}")
            run_summary["results"].append({
                "file": sbom_name,
                "status": "FAILED",
                "reason": "Project creation failed"
            })
            continue

        # Upload BOM
        try:
            result = upload_bom(project["uuid"], sbom_path)

            if not result.get("success", False):
                reason = result.get("response", "Unknown error")
                logger.error(
                    f"BOM upload failed | file={sbom_name} | "
                    f"status={result.get('status_code')} | reason={reason}"
                )

                run_summary["results"].append({
                    "file": sbom_name,
                    "status": "FAILED",
                    "reason": reason
                })
                continue

        except Exception as ex:
            logger.exception(f"Unexpected error uploading {sbom_name}")
            run_summary["results"].append({
                "file": sbom_name,
                "status": "FAILED",
                "reason": str(ex)
            })
            continue

        # Success
        registry["uploads"][sbom_hash] = {
            "file": sbom_name,
            "version": version,
            "uploaded_at": utc_now(),
            "project_uuid": project["uuid"],
            "status": "UPLOADED"
        }

        run_summary["results"].append({
            "file": sbom_name,
            "status": "UPLOADED",
            "version": version,
            "hash": sbom_hash
        })

        logger.info(f"Upload successful: {sbom_name} → version {version}")
        current_version = version

    # ------------------------------------------------------
    # Persist state
    # ------------------------------------------------------
    save_json(registry_path, registry)
    save_json(summary_path, run_summary)

    logger.info("Automation run completed")


def main():
    root = get_automation_root()

    for entry in os.listdir(root):
        app_path = os.path.join(root, entry)
        if os.path.isdir(app_path):
            process_application(app_path)


if __name__ == "__main__":
    main()
