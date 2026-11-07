import hashlib
from database_manager import load_signatures
from logger_utility import log_alert

def get_file_hash(filepath):
    """Calculates the MD5 hash of a file by reading in binary mode."""
    hasher = hashlib.md5()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None

def scan_file(filepath):
    """
    Generalized Scanner:
    1. Checks MD5 Hash.
    2. Decodes binary content to string to find signatures in ANY file type.
    """
    sigs = load_signatures()
    
    # 1. Hash Check
    file_hash = get_file_hash(filepath)
    if file_hash in sigs["hashes"]:
        log_alert(f"CRITICAL THREAT: Malicious Hash in {filepath}", "CRITICAL")
        return True

    # 2. Content Search (Works for .py, .txt, etc.)
    try:
        with open(filepath, 'rb') as f:
            # decode with 'ignore' allows us to read non-text files safely
            content = f.read().decode('utf-8', errors='ignore')
            for pattern in sigs["strings"]:
                if pattern.lower() in content.lower():
                    log_alert(f"THREAT DETECTED: String '{pattern}' found in {filepath}", "WARNING")
                    return True
    except Exception as e:
        log_alert(f"Could not scan {filepath}: {e}", "ERROR")

    return False
