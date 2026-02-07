"""
Request Utilities

Helper functions for making HTTP requests and handling responses.
"""

import re
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

try:
    import requests
    from requests import Session, Response
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    Session = None
    Response = None


def create_session(proxy: Optional[str] = None,
                   verify_ssl: bool = True) -> Optional['Session']:
    """
    Create a requests session with optional proxy.

    Args:
        proxy: Proxy URL (e.g., "http://127.0.0.1:8080" for Burp)
        verify_ssl: Whether to verify SSL certificates

    Returns:
        Configured requests Session
    """
    if not REQUESTS_AVAILABLE:
        print("Warning: requests library not available")
        return None

    session = requests.Session()

    if proxy:
        session.proxies = {
            "http": proxy,
            "https": proxy,
        }

    session.verify = verify_ssl

    # Common headers
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    })

    return session


def send_request(url: str,
                 method: str = "GET",
                 data: Optional[Dict] = None,
                 headers: Optional[Dict] = None,
                 cookies: Optional[Dict] = None,
                 session: Optional['Session'] = None,
                 follow_redirects: bool = True,
                 timeout: int = 10) -> Optional['Response']:
    """
    Send an HTTP request.

    Args:
        url: Target URL
        method: HTTP method
        data: Request body data
        headers: Additional headers
        cookies: Cookies to send
        session: Existing session to use
        follow_redirects: Whether to follow redirects
        timeout: Request timeout in seconds

    Returns:
        Response object or None on error
    """
    if not REQUESTS_AVAILABLE:
        print("Warning: requests library not available")
        return None

    if session is None:
        session = requests.Session()

    try:
        response = session.request(
            method=method.upper(),
            url=url,
            data=data,
            headers=headers or {},
            cookies=cookies,
            allow_redirects=follow_redirects,
            timeout=timeout,
        )
        return response
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return None


def extract_csrf_token(html: str,
                       token_names: Optional[list] = None) -> Optional[str]:
    """
    Extract CSRF token from HTML.

    Args:
        html: HTML content
        token_names: List of possible token field names

    Returns:
        CSRF token value or None
    """
    if token_names is None:
        token_names = [
            "csrf_token", "csrftoken", "_csrf", "csrf",
            "authenticity_token", "_token", "token",
            "csrfmiddlewaretoken",
        ]

    # Try input fields
    for name in token_names:
        # name attribute
        pattern = rf'<input[^>]*name=["\']?{name}["\']?[^>]*value=["\']?([^"\'>\s]+)'
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)

        # value before name
        pattern = rf'<input[^>]*value=["\']?([^"\'>\s]+)[^>]*name=["\']?{name}'
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)

    # Try meta tags
    pattern = r'<meta[^>]*name=["\']?csrf-token["\']?[^>]*content=["\']?([^"\'>\s]+)'
    match = re.search(pattern, html, re.IGNORECASE)
    if match:
        return match.group(1)

    return None


def parse_cookies(cookie_string: str) -> Dict[str, str]:
    """
    Parse a cookie string into a dictionary.

    Args:
        cookie_string: Cookie header value

    Returns:
        Dictionary of cookie name-value pairs
    """
    cookies = {}
    for item in cookie_string.split(';'):
        item = item.strip()
        if '=' in item:
            name, value = item.split('=', 1)
            cookies[name.strip()] = value.strip()
    return cookies


def extract_links(html: str, base_url: str) -> list:
    """
    Extract all links from HTML.

    Args:
        html: HTML content
        base_url: Base URL for relative links

    Returns:
        List of absolute URLs
    """
    links = []
    pattern = r'href=["\']([^"\']+)["\']'

    for match in re.finditer(pattern, html, re.IGNORECASE):
        link = match.group(1)
        if not link.startswith(('javascript:', 'mailto:', '#')):
            absolute_url = urljoin(base_url, link)
            links.append(absolute_url)

    return list(set(links))


def extract_forms(html: str) -> list:
    """
    Extract form information from HTML.

    Args:
        html: HTML content

    Returns:
        List of form dictionaries with action, method, and inputs
    """
    forms = []
    form_pattern = r'<form[^>]*>(.*?)</form>'

    for form_match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
        form_html = form_match.group(0)
        form_content = form_match.group(1)

        # Extract action
        action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        action = action_match.group(1) if action_match else ""

        # Extract method
        method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
        method = method_match.group(1).upper() if method_match else "GET"

        # Extract inputs
        inputs = []
        input_pattern = r'<input[^>]*>'
        for input_match in re.finditer(input_pattern, form_content, re.IGNORECASE):
            input_html = input_match.group(0)

            name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            value_match = re.search(r'value=["\']([^"\']*)["\']', input_html, re.IGNORECASE)

            inputs.append({
                "name": name_match.group(1) if name_match else "",
                "type": type_match.group(1) if type_match else "text",
                "value": value_match.group(1) if value_match else "",
            })

        forms.append({
            "action": action,
            "method": method,
            "inputs": inputs,
        })

    return forms


def detect_waf(response: 'Response') -> Optional[str]:
    """
    Detect Web Application Firewall from response.

    Args:
        response: HTTP response object

    Returns:
        WAF name if detected, None otherwise
    """
    if response is None:
        return None

    headers = {k.lower(): v for k, v in response.headers.items()}
    body = response.text.lower()

    waf_signatures = {
        "Cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
        "AWS WAF": ["x-amzn-requestid", "awswaf"],
        "Akamai": ["akamai", "ak_bmsc"],
        "Imperva": ["incap_ses", "_incap_", "imperva"],
        "F5 BIG-IP": ["x-wa-info", "bigip"],
        "ModSecurity": ["mod_security", "modsecurity"],
    }

    for waf, signatures in waf_signatures.items():
        for sig in signatures:
            if sig in str(headers) or sig in body:
                return waf

    return None


if __name__ == "__main__":
    # Example usage
    if REQUESTS_AVAILABLE:
        session = create_session()
        response = send_request("https://httpbin.org/get", session=session)
        if response:
            print(f"Status: {response.status_code}")
            print(f"Headers: {dict(response.headers)}")
