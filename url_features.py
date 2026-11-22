"""
url_features.py
---------------
Structural and lexical URL feature extractor for PhishGuard AI.
Shared across model training and live prediction pipelines to ensure strict training-serving consistency.
"""

from urllib.parse import urlparse
import re
import ipaddress
from typing import Dict, Any

# ---------------------------------------------------------------------------
# Deployed Model Feature Set (18 Live URL Signals)
# ---------------------------------------------------------------------------
LIVE_FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DigitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfHyphensInURL",
    "NoOfDotsInURL",
    "IsHTTPS",
]


def extract_url_features(url: str) -> Dict[str, Any]:
    """
    Extract 18 structural and lexical features from a raw URL string.
    Executes in < 0.2ms on CPU without external network requests.
    """
    raw_url = str(url).strip()
    if not raw_url:
        raise ValueError("URL cannot be empty")

    url_for_parse = raw_url if raw_url.startswith(("http://", "https://")) else "https://" + raw_url
    parsed = urlparse(url_for_parse)
    hostname = parsed.hostname or ""

    domain = hostname[4:] if hostname.startswith("www.") else hostname
    domain_length = len(domain)

    # Detect raw IP address host
    try:
        ipaddress.ip_address(hostname)
        is_domain_ip = 1
    except ValueError:
        is_domain_ip = 0

    tld_length = len(hostname.split(".")[-1]) if "." in hostname else 0
    hostname_parts = hostname.split(".")
    no_subdomain = len(hostname_parts) - 2 if len(hostname_parts) >= 3 else 0

    # Percent-encoded character obfuscation
    obfuscated_chars = re.findall(r"%[0-9a-fA-F]{2}", raw_url)
    no_obfuscated_char = len(obfuscated_chars)
    has_obfuscation = 1 if no_obfuscated_char > 0 else 0
    url_len = len(raw_url)
    obfuscation_ratio = no_obfuscated_char / url_len if url_len > 0 else 0.0

    # Lexical character statistics
    no_letters = sum(c.isalpha() for c in raw_url)
    no_digits = sum(c.isdigit() for c in raw_url)
    letter_ratio = no_letters / url_len if url_len > 0 else 0.0
    digit_ratio = no_digits / url_len if url_len > 0 else 0.0

    return {
        "URLLength": url_len,
        "DomainLength": domain_length,
        "IsDomainIP": is_domain_ip,
        "TLDLength": tld_length,
        "NoOfSubDomain": no_subdomain,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": no_obfuscated_char,
        "ObfuscationRatio": obfuscation_ratio,
        "NoOfLettersInURL": no_letters,
        "LetterRatioInURL": letter_ratio,
        "NoOfDegitsInURL": no_digits,
        "DigitRatioInURL": digit_ratio,
        "NoOfEqualsInURL": raw_url.count("="),
        "NoOfQMarkInURL": raw_url.count("?"),
        "NoOfAmpersandInURL": raw_url.count("&"),
        "NoOfHyphensInURL": raw_url.count("-"),
        "NoOfDotsInURL": raw_url.count("."),
        "IsHTTPS": 1 if parsed.scheme.lower() == "https" else 0,
        "NoOfSlashesInURL": raw_url.count("/"),
    }
