import json
import os

DB_FILE = "database.json"

def initialize_db():
    """
    Ensures the database file exists. 
    Logic: Checks for file existence, creates a default template if missing.
    """
    if not os.path.exists(DB_FILE):
        default_data = {"hashes": [], "strings": []}
        with open(DB_FILE, 'w') as f:
            json.dump(default_data, f, indent=4)
        print(f"[+] Created fresh database: {DB_FILE}")

def add_signature(value, sig_type="hash"):
    """
    Adds a new signature to the database.
    Logic: Loads JSON, appends to the correct list (hash or string), and saves.
    """
    # 1. Load the current data from the file
    try:
        with open(DB_FILE, 'r') as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Fallback if file is missing or corrupted
        data = {"hashes": [], "strings": []}

    # 2. Update the correct list based on type
    if sig_type == "hash":
        if value not in data["hashes"]:
            data["hashes"].append(value)
    else:
        if value not in data["strings"]:
            data["strings"].append(value)

    # 3. Save the entire updated dictionary back to the file
    # Opening with 'w' automatically handles the truncation/overwriting
    with open(DB_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def load_signatures():
    """
    Retrieves all signatures for the scanner.
    Logic: Returns the full dictionary from the JSON file.
    """
    try:
        with open(DB_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"hashes": [], "strings": []}

def remove_signature(value, sig_type="hash"):
    """
    Helper function to delete a signature if needed.
    """
    with open(DB_FILE, 'r') as f:
        data = json.load(f)

    category = "hashes" if sig_type == "hash" else "strings"
    
    if value in data[category]:
        data[category].remove(value)
        with open(DB_FILE, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    return False
