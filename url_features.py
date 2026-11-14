"""
url_features.py
---------------
URL feature extractor for the Phishing URL Detector.

This module is shared by both predictor.py (live prediction)
and retrain.py (model retraining) to guarantee training-serving
consistency.

IMPORTANT: If you modify any feature definition here, you MUST
re-run retrain.py to retrain the model. Do not change features
in the live extractor without retraining.
"""

from urllib.parse import urlparse
import re
import ipaddress


# ---------------------------------------------------------------------------
# Feature list — 18 URL-based features used by the deployed model.
# IsHTTPS is extracted but intentionally excluded from this list
# due to dataset-specific bias (all legitimate samples had HTTPS).
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
    # IsHTTPS re-added: originally removed due to 40% importance (too dominant).
    # Now one of 18 features — helps distinguish http-phishing from https-legitimate
    # without being the single deciding factor.
    "IsHTTPS",
    # NoOfSlashesInURL intentionally excluded:
    # All legitimate PhiUSIIL URLs have no path (2 slashes). Including this
    # feature caused the model to flag any URL with a path/trailing slash.
]


# ---------------------------------------------------------------------------
# Feature extractor
# ---------------------------------------------------------------------------

def extract_url_features(url):
    """
    Extract 19 URL-based structural features from a URL string.
    (18 live features + IsHTTPS, which is excluded at model selection time.)

    Parameters
    ----------
    url : str
        Raw URL string from user input or dataset.

    Returns
    -------
    dict
        Feature name → value mapping with 19 keys.

    Raises
    ------
    ValueError
        If the URL string is empty.
    """
    url = str(url).strip()

    if not url:
        raise ValueError("URL cannot be empty")

    # Prepend scheme for parsing only; URLLength uses the original input.
    if not url.startswith(("http://", "https://")):
        url_for_parse = "https://" + url
    else:
        url_for_parse = url

    parsed = urlparse(url_for_parse)
    hostname = parsed.hostname or ""

    # DomainLength: strip leading www. before measuring
    domain = hostname
    if domain.startswith("www."):
        domain = domain[4:]
    domain_length = len(domain)

    # Detect raw IP address as hostname
    try:
        ipaddress.ip_address(hostname)
        is_domain_ip = 1
    except ValueError:
        is_domain_ip = 0

    # TLD length
    tld_length = len(hostname.split(".")[-1]) if "." in hostname else 0

    # Subdomain count (simplified: parts beyond domain + TLD)
    hostname_parts = hostname.split(".")
    no_subdomain = len(hostname_parts) - 2 if len(hostname_parts) >= 3 else 0

    # Percent-encoded (obfuscated) characters
    obfuscated_chars = re.findall(r"%[0-9a-fA-F]{2}", url)
    no_obfuscated_char = len(obfuscated_chars)
    has_obfuscation = 1 if no_obfuscated_char > 0 else 0
    url_len = len(url)
    obfuscation_ratio = no_obfuscated_char / url_len if url_len > 0 else 0

    # Character counts
    no_letters   = sum(c.isalpha() for c in url)
    no_digits    = sum(c.isdigit() for c in url)
    no_equals    = url.count("=")
    no_qmark     = url.count("?")
    no_ampersand = url.count("&")

    # --- New features (v2) ---
    letter_ratio  = no_letters / url_len if url_len > 0 else 0
    digit_ratio   = no_digits  / url_len if url_len > 0 else 0
    no_hyphens    = url.count("-")
    no_dots       = url.count(".")
    no_slashes    = url.count("/")

    return {
        "URLLength":          url_len,
        "DomainLength":       domain_length,
        "IsDomainIP":         is_domain_ip,
        "TLDLength":          tld_length,
        "NoOfSubDomain":      no_subdomain,
        "HasObfuscation":     has_obfuscation,
        "NoOfObfuscatedChar": no_obfuscated_char,
        "ObfuscationRatio":   obfuscation_ratio,
        "NoOfLettersInURL":   no_letters,
        "LetterRatioInURL":   letter_ratio,
        "NoOfDegitsInURL":    no_digits,
        "DigitRatioInURL":    digit_ratio,
        "NoOfEqualsInURL":    no_equals,
        "NoOfQMarkInURL":     no_qmark,
        "NoOfAmpersandInURL": no_ampersand,
        "NoOfHyphensInURL":   no_hyphens,
        "NoOfDotsInURL":      no_dots,
        "NoOfSlashesInURL":   no_slashes,
        # Extracted but excluded from live model (dataset-specific bias)
        "IsHTTPS": 1 if parsed.scheme.lower() == "https" else 0,
    }
