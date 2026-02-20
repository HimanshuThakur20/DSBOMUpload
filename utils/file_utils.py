# utils/file_utils.py
import os

def file_exists(filepath):
    """Checks if the given file path exists and is accessible."""
    return os.path.isfile(filepath)
