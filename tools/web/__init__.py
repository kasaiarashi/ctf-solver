"""
Web Exploitation Tools

Utilities for web security testing and exploitation.
"""

from .sqli_helper import (
    sqli_payloads,
    union_payload,
    boolean_payload,
    time_payload,
    error_payload,
)
from .xss_payloads import (
    xss_basic,
    xss_filter_bypass,
    xss_cookie_steal,
    xss_keylogger,
)
from .request_utils import (
    create_session,
    send_request,
    extract_csrf_token,
    parse_cookies,
)

__all__ = [
    # SQLi
    "sqli_payloads",
    "union_payload",
    "boolean_payload",
    "time_payload",
    "error_payload",
    # XSS
    "xss_basic",
    "xss_filter_bypass",
    "xss_cookie_steal",
    "xss_keylogger",
    # Request utils
    "create_session",
    "send_request",
    "extract_csrf_token",
    "parse_cookies",
]
