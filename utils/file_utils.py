# utils/file_utils.py
import os

def file_exists(filepath):
    return os.path.isfile(filepath)


def validate_file_path(filepath: str):
    """
    Full validation for Phase 1.
    Returns (True, "") if valid, else (False, "error message")
    """
    # 1. Check type
    if not filepath or not isinstance(filepath, str):
        return False, "Invalid file path. Expected a non-empty string."

    # 2. Check exists
    if not os.path.exists(filepath):
        return False, f"File does not exist: {filepath}"

    # 3. Reject directories
    if not os.path.isfile(filepath):
        return False, f"Path is not a file: {filepath}"

    # 4. Check read permissions
    if not os.access(filepath, os.R_OK):
        return False, f"File is not readable: {filepath}"

    return True, ""
