from __future__ import annotations

import ipaddress
import math
import re
import socket
import ssl
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import List, Tuple
from urllib.parse import urljoin, urlparse

import requests

try:
    import whois  # optional
except Exception:
    whois = None


SHORTENING_DOMAINS = {
    "bit.ly", "goo.gl", "t.co", "tinyurl.com", "ow.ly", "buff.ly",
    "is.gd", "cutt.ly", "rebrand.ly", "rb.gy", "s.id", "lnkd.in",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "password",
    "bank",
    "wallet",
    "account",
    "secure",
    "update",
    "reward",
    "gift",
    "free",
    "payment",
    "billing",
    "crypto",
    "bitcoin",
    "otp",
    "netbanking",
    "upi",
    "support",
    "refund",
}

SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".top", ".xyz", ".click", ".tk", ".gq", ".ml", ".cf",
    ".cam", ".work", ".support",
}

POPULAR_BRANDS = [
    "google",
    "paypal",
    "amazon",
    "microsoft",
    "apple",
    "facebook",
    "instagram",
    "netflix",
]

URL_SUSPICIOUS_TERMS = (
    "login", "signin", "sign-in", "verify", "verification", "password",
    "secure", "security", "update", "account", "wallet", "bank", "payment",
    "billing", "otp", "support", "confirm", "auth", "reset",
)


class SimpleHTMLAnalyzer(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title = ""
        self.in_title = False
        self.links: List[str] = []
        self.forms: List[Tuple[str, str]] = []
        self.scripts: List[str] = []
        self.inputs: List[dict] = []
        self.iframes: List[dict] = []
        self.meta_refresh: List[str] = []
        self.text_chunks: List[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()

        if tag == "title":
            self.in_title = True
        elif tag == "a" and "href" in attrs:
            self.links.append(attrs["href"])
        elif tag == "form":
            action = attrs.get("action", "")
            method = attrs.get("method", "get")
            self.forms.append((action, method))
        elif tag == "script" and "src" in attrs:
            self.scripts.append(attrs["src"])
        elif tag == "input":
            self.inputs.append(attrs)
        elif tag == "iframe":
            self.iframes.append(attrs)
        elif tag == "meta":
            http_equiv = attrs.get("http-equiv", "").lower()
            content = attrs.get("content", "")
            if http_equiv == "refresh":
                self.meta_refresh.append(content)

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data.strip() + " "
        text = data.strip()
        if text:
            self.text_chunks.append(text)


def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        url = "http://" + url
    return url


def extract_hostname(url: str) -> str:
    return urlparse(url).hostname or ""


def is_ip_hostname(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except Exception:
        return False


def count_subdomains(hostname: str) -> int:
    parts = hostname.split(".")
    return max(0, len(parts) - 2)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def get_domain_age_days(hostname: str) -> int | None:
    if not whois:
        return None

    try:
        domain_info = whois.whois(hostname)
        creation_date = getattr(domain_info, "creation_date", None)

        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None

        if not creation_date:
            return None

        if creation_date.tzinfo is not None:
            creation_date = creation_date.astimezone(timezone.utc).replace(tzinfo=None)

        now_utc = datetime.utcnow()
        return max(0, (now_utc - creation_date).days)
    except Exception:
        return None


def get_ssl_info(hostname: str) -> tuple[bool, str, int | None]:
    if not hostname or is_ip_hostname(hostname):
        return False, "", None

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        issuer = ""
        issuer_parts = cert.get("issuer", ())
        flat_parts = []
        for rdn in issuer_parts:
            for item in rdn:
                if len(item) == 2:
                    flat_parts.append(f"{item[0]}={item[1]}")
        issuer = ", ".join(flat_parts)

        days_left = None
        not_after = cert.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.utcnow()).days
            except Exception:
                days_left = None

        return True, issuer, days_left
    except Exception:
        return False, "", None


def fetch_page(url: str) -> tuple[bool, int | None, str, str, str, int]:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0 Safari/537.36"
        )
    }

    try:
        response = requests.get(url, timeout=8, headers=headers, allow_redirects=True)
        final_url = response.url
        status_code = response.status_code
        content_type = response.headers.get("content-type", "")
        html = response.text if "text/html" in content_type or "<html" in response.text.lower() else response.text
        redirect_count = len(response.history)
        return True, status_code, final_url, html, "", redirect_count
    except Exception as exc:
        return False, None, url, "", str(exc), 0


def analyze_page_content(html: str, base_url: str) -> tuple[list[str], int]:
    notes: list[str] = []
    parser = SimpleHTMLAnalyzer()

    try:
        parser.feed(html)
    except Exception:
        pass

    title = parser.title.strip()
    text = " ".join(parser.text_chunks).lower()
    base_host = extract_hostname(base_url)

    if title:
        notes.append(f"Page title found: '{title[:80]}'")
    else:
        notes.append("No page title found.")

    if any(k in text for k in ("login", "sign in", "verify", "password", "account")):
        notes.append("Page text contains login/account-related keywords.")

    if any(word in text for word in ("urgent", "suspended", "lock", "expired", "final warning", "immediately")):
        notes.append("Urgent or threatening language detected.")

    if "javascript:" in html.lower():
        notes.append("JavaScript URLs were found in the page source.")

    # Forms
    forms_same_domain = 0
    forms_other_domain = 0
    password_fields = 0

    for attrs in parser.inputs:
        input_type = str(attrs.get("type", "")).lower()
        if input_type == "password":
            password_fields += 1

    for action, method in parser.forms:
        action = action.strip()
        if not action or action in ("#", "javascript:void(0)"):
            forms_same_domain += 1
            continue

        target = urljoin(base_url, action)
        target_host = extract_hostname(target)
        if target_host and base_host and target_host.lower() == base_host.lower():
            forms_same_domain += 1
        else:
            forms_other_domain += 1

    if parser.forms:
        notes.append(f"Forms detected: {len(parser.forms)}")
        if forms_other_domain:
            notes.append("At least one form submits to a different domain.")
    else:
        notes.append("No HTML forms detected.")

    if password_fields:
        notes.append(f"Password input field(s) detected: {password_fields}")

    # External resources
    external_links = 0
    for link in parser.links + parser.scripts:
        if not link:
            continue
        resolved = urljoin(base_url, link)
        host = extract_hostname(resolved)
        if host and base_host and host.lower() != base_host.lower():
            external_links += 1

    if external_links:
        notes.append(f"External resources detected: {external_links}")
    else:
        notes.append("No obvious external resource usage detected.")

    # Iframes / redirect tricks
    hidden_iframes = 0
    for attrs in parser.iframes:
        style = str(attrs.get("style", "")).lower()
        hidden_attr = "hidden" in attrs
        zero_sized = any(
            token in style
            for token in ("display:none", "visibility:hidden", "width:0", "height:0", "opacity:0")
        )
        if hidden_attr or zero_sized:
            hidden_iframes += 1

    if parser.iframes:
        notes.append(f"Iframe(s) detected: {len(parser.iframes)}")
    if hidden_iframes:
        notes.append(f"Hidden iframe(s) detected: {hidden_iframes}")

    if parser.meta_refresh:
        notes.append("Meta refresh redirect detected.")

    # Content risk
    content_risk = 0
    content_risk += min(25, 10 * forms_other_domain)
    content_risk += min(15, 3 * external_links)
    content_risk += min(12, 4 * password_fields)
    content_risk += min(10, 5 * hidden_iframes)
    content_risk += min(8, 4 * len(parser.meta_refresh))

    if any(word in text for word in ("urgent", "suspended", "lock", "expired", "final warning", "immediately")):
        content_risk += 10

    return notes, content_risk


def analyze_website(url: str) -> dict:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    hostname = parsed.hostname or ""

    url_checks: list[str] = []
    content_checks: list[str] = []
    recommendations: list[str] = []

    risk = 0
    domain_age_days = None
    ssl_valid = False
    ssl_issuer = ""
    ssl_days_left = None
    redirect_count = 0
    entropy_score = 0.0

    if not hostname:
        return {
            "normalized_url": normalized,
            "hostname": hostname,
            "final_url": normalized,
            "status_code": None,
            "page_title": "",
            "reachable": False,
            "risk_score": 0,
            "risk_label": "Low",
            "summary": "The URL could not be parsed.",
            "url_checks": ["Invalid URL format."],
            "content_checks": [],
            "recommendations": ["Enter a valid website address."],
            "page_text": "",
            "domain_age_days": None,
            "ssl_valid": False,
            "ssl_issuer": "",
            "ssl_days_left": None,
            "redirect_count": 0,
            "entropy": 0.0,
        }

    hostname_lower = hostname.lower()
    entropy_score = shannon_entropy(hostname_lower)

    # URL-based checks
    length = len(normalized)
    if length > 75:
        url_checks.append(f"Long URL length detected ({length} characters).")
        risk += 8

    if is_ip_hostname(hostname):
        url_checks.append("Hostname is an IP address instead of a domain name.")
        risk += 25

    if hostname.startswith("xn--") or "xn--" in hostname_lower:
        url_checks.append("Punycode / internationalized domain detected.")
        risk += 12

    subdomains = count_subdomains(hostname)
    if subdomains >= 3:
        url_checks.append(f"Many subdomains detected ({subdomains}).")
        risk += 10

    if "-" in hostname:
        url_checks.append("Hyphen used in the domain name.")
        risk += 4

    if normalized.lower().startswith("http://"):
        url_checks.append("No HTTPS in the input URL.")
        risk += 10

    if any(domain in hostname_lower for domain in SHORTENING_DOMAINS):
        url_checks.append("URL shortening service detected.")
        risk += 18

    if any(keyword in normalized.lower() for keyword in SUSPICIOUS_KEYWORDS):
        url_checks.append("Suspicious keyword(s) found in the URL.")
        risk += 12

    if any(normalized.lower().endswith(tld) for tld in SUSPICIOUS_TLDS):
        url_checks.append("Suspicious-looking top-level domain detected.")
        risk += 8

    if "@" in normalized:
        url_checks.append("At-sign detected in the URL.")
        risk += 15

    if normalized.count(".") >= 5:
        url_checks.append("Very high number of dots in the URL.")
        risk += 8

    if entropy_score > 4.0:
        url_checks.append("Domain looks randomly generated (high entropy).")
        risk += 10

    # Brand impersonation-style signal
    for brand in POPULAR_BRANDS:
        if brand in hostname_lower and any(term in normalized.lower() for term in URL_SUSPICIOUS_TERMS):
            if brand not in hostname_lower.split(".")[0]:
                url_checks.append(f"Possible {brand} impersonation attempt.")
                risk += 12
                break

    if not url_checks:
        url_checks.append("No major URL-based warning signs detected.")

    # SSL and domain age
    domain_age_days = get_domain_age_days(hostname)
    ssl_valid, ssl_issuer, ssl_days_left = get_ssl_info(hostname)

    if domain_age_days is not None:
        if domain_age_days < 30:
            url_checks.append(f"Very new domain ({domain_age_days} days old).")
            risk += 25
        elif domain_age_days < 180:
            url_checks.append(f"Recently registered domain ({domain_age_days} days old).")
            risk += 10

    if ssl_valid:
        content_checks.append(
            f"SSL certificate detected{f' (issuer: {ssl_issuer})' if ssl_issuer else ''}."
        )
        if ssl_days_left is not None and ssl_days_left < 30:
            content_checks.append(f"SSL certificate expires soon ({ssl_days_left} days left).")
            risk += 6
    else:
        content_checks.append("SSL certificate validation failed or could not be verified.")
        risk += 15

    # Fetch page
    reachable, status_code, final_url, html, fetch_error, redirect_count = fetch_page(normalized)
    final_hostname = extract_hostname(final_url)

    if redirect_count > 0:
        content_checks.append(f"Redirect chain detected ({redirect_count} redirect(s)).")
        if redirect_count > 3:
            risk += 10

    if final_hostname and final_hostname.lower() != hostname_lower:
        content_checks.append("Final page host differs from the original host after redirects.")
        risk += 8

    page_title = ""
    page_text = ""
    if reachable and html:
        analyzer = SimpleHTMLAnalyzer()
        try:
            analyzer.feed(html)
        except Exception:
            pass

        page_title = analyzer.title.strip()
        page_text = " ".join(analyzer.text_chunks)

        notes, content_risk = analyze_page_content(html, final_url)
        content_checks.extend(notes)
        risk += content_risk

        if status_code and status_code >= 400:
            content_checks.append(f"Server returned HTTP {status_code}.")
            risk += 4
    else:
        content_checks.append(f"Could not fetch page content: {fetch_error or 'unknown error'}")
        risk += 5

    risk = max(0, min(100, risk))

    if risk >= 70:
        risk_label = "High"
        summary = "Multiple phishing indicators were found. Treat this website as unsafe."
        recommendations = [
            "Do not enter passwords, OTPs, card details, or personal data.",
            "Verify the site address independently before continuing.",
            "Close the page if it asks for urgent login, payment, or verification.",
        ]
    elif risk >= 40:
        risk_label = "Medium"
        summary = "Some suspicious signs were found. Verify carefully before trusting this website."
        recommendations = [
            "Double-check the domain spelling and HTTPS certificate.",
            "Open the site from a trusted bookmark or official app.",
            "Avoid submitting sensitive details unless you are sure it is legitimate.",
        ]
    else:
        risk_label = "Low"
        summary = "Few phishing signals were found in the checks performed."
        recommendations = [
            "Still verify the domain before sharing sensitive information.",
            "Look for HTTPS and correct spelling in the address bar.",
        ]

    return {
        "normalized_url": normalized,
        "hostname": hostname,
        "final_url": final_url,
        "status_code": status_code,
        "page_title": page_title,
        "reachable": reachable,
        "risk_score": risk,
        "risk_label": risk_label,
        "summary": summary,
        "url_checks": url_checks,
        "content_checks": content_checks,
        "recommendations": recommendations,
        "page_text": page_text,
        "domain_age_days": domain_age_days,
        "ssl_valid": ssl_valid,
        "ssl_issuer": ssl_issuer,
        "ssl_days_left": ssl_days_left,
        "redirect_count": redirect_count,
        "entropy": round(entropy_score, 2),
    }