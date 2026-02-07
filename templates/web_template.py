#!/usr/bin/env python3
"""
Web Exploit Template

Usage:
    python exploit.py
    python exploit.py --url http://target:8080
    python exploit.py --proxy http://127.0.0.1:8080
"""

import argparse
import requests
from urllib.parse import urljoin

# =============================================================================
# Configuration
# =============================================================================

TARGET_URL = 'http://localhost:8080'
PROXY = None  # Set to 'http://127.0.0.1:8080' for Burp

# =============================================================================
# Setup
# =============================================================================

def get_session(proxy=None):
    """Create a requests session with optional proxy."""
    session = requests.Session()

    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
        session.verify = False

    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    })

    return session


# =============================================================================
# Helper Functions
# =============================================================================

def login(session, base_url, username, password):
    """Login and get session."""
    url = urljoin(base_url, '/login')
    data = {
        'username': username,
        'password': password,
    }
    resp = session.post(url, data=data)
    return resp.status_code == 200


def extract_csrf(html):
    """Extract CSRF token from HTML."""
    import re
    match = re.search(r'name=["\']?csrf[_-]?token["\']?\s+value=["\']([^"\']+)', html)
    return match.group(1) if match else None


def find_flag(text):
    """Search for flag pattern in text."""
    import re
    patterns = [
        r'flag\{[^\}]+\}',
        r'CTF\{[^\}]+\}',
        r'picoCTF\{[^\}]+\}',
        r'HTB\{[^\}]+\}',
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(0)
    return None


# =============================================================================
# Exploit
# =============================================================================

def exploit(base_url, session):
    """
    Main exploitation logic.

    Vulnerability: [DESCRIBE VULNERABILITY]
    Strategy: [DESCRIBE EXPLOITATION STRATEGY]
    """

    # -------------------------------------------------------------------------
    # Stage 1: Reconnaissance
    # -------------------------------------------------------------------------

    # resp = session.get(base_url)
    # print(f"[*] Status: {resp.status_code}")
    # print(f"[*] Server: {resp.headers.get('Server', 'Unknown')}")

    # -------------------------------------------------------------------------
    # Stage 2: Exploitation
    # -------------------------------------------------------------------------

    # Example: SQL Injection
    # payload = "' OR '1'='1"
    # resp = session.get(f"{base_url}/search?q={payload}")

    # Example: Command Injection
    # payload = "; cat /flag.txt"
    # resp = session.post(f"{base_url}/exec", data={'cmd': payload})

    # Example: SSTI
    # payload = "{{7*7}}"
    # resp = session.get(f"{base_url}/render?template={payload}")

    # -------------------------------------------------------------------------
    # Stage 3: Extract Flag
    # -------------------------------------------------------------------------

    # flag = find_flag(resp.text)
    # if flag:
    #     print(f"[+] FLAG: {flag}")
    # else:
    #     print("[-] Flag not found")
    #     print(resp.text)

    pass


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Web Exploit')
    parser.add_argument('--url', default=TARGET_URL, help='Target URL')
    parser.add_argument('--proxy', default=PROXY, help='Proxy URL (e.g., http://127.0.0.1:8080)')
    args = parser.parse_args()

    print(f"[*] Target: {args.url}")
    if args.proxy:
        print(f"[*] Proxy: {args.proxy}")

    session = get_session(args.proxy)

    try:
        exploit(args.url, session)
    except requests.exceptions.RequestException as e:
        print(f"[-] Request error: {e}")
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
