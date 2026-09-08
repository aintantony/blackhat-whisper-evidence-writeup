#!/usr/bin/env python3
"""
Automated solution script for Whisper Evidence challenge
BlackHat MEA Qualification CTF 2026
Author: aintantony
"""

import sys
import hashlib
import base64

try:
    import pyzipper
except ImportError:
    print("Error: pyzipper not installed. Run: pip install pyzipper")
    sys.exit(1)


def derive_password(plaintext_password: str) -> bytes:
    """
    Derive the actual encryption password from the plaintext password.
    Uses blake2b hash with digest_size=32, takes first 20 hex characters.
    """
    return hashlib.blake2b(
        plaintext_password.encode(),
        digest_size=32
    ).hexdigest()[:20].encode()


def extract_and_find_flag(zip_path: str, password: bytes) -> str:
    """
    Extract the encrypted archive and search for the flag in internal_api_keys.csv
    """
    with pyzipper.AESZipFile(zip_path) as zf:
        zf.setpassword(password)
        
        # Read the internal_api_keys.csv file
        content = zf.read('internal_api_keys.csv').decode('utf-8')
        
        # Find the master_vault entry with base64 encoded flag
        for line in content.split('\n'):
            if 'master_vault' in line:
                parts = line.split(',')
                if len(parts) >= 2:
                    encoded_flag = parts[1]
                    # Decode base64
                    flag = base64.b64decode(encoded_flag).decode('utf-8')
                    return flag
    
    return None


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 solve.py <path_to_session.zip>")
        print("\nExample:")
        print("  python3 solve.py ./home/dwright/.cache/fontconfig/session.zip")
        sys.exit(1)
    
    zip_path = sys.argv[1]
    
    print("[*] Whisper Evidence Solver")
    print("[*] BlackHat MEA Qualification CTF 2026\n")
    
    # The password found in Ollama history
    plaintext_password = "Gr33nF0x42!D1amond"
    print(f"[+] Plaintext password from Ollama history: {plaintext_password}")
    
    # Derive the actual encryption password
    derived_password = derive_password(plaintext_password)
    print(f"[+] Derived encryption password: {derived_password.decode()}")
    
    # Extract and find flag
    print(f"[*] Extracting archive: {zip_path}")
    flag = extract_and_find_flag(zip_path, derived_password)
    
    if flag:
        print(f"\n[!] FLAG FOUND: {flag}")
    else:
        print("\n[-] Flag not found in archive")
        sys.exit(1)


if __name__ == "__main__":
    main()
