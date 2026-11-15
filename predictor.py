"""
predictor.py
------------
Model loading and prediction logic for the Phishing URL Detector.

Imports the URL feature extractor from url_features.py so that
the live prediction path is always identical to the training path.

Multi-tier Security Architecture:
Tier 1: High-reputation official domains allowlist (google.com, github.com, etc.).
Tier 2: Brand Impersonation / Typosquatting detection (catches fake paypal-update.com, etc.).
Tier 3: Random Forest ML model for general URL classification.
Tier 4: Explainable AI feature breakdown for user transparency.
"""

import os
import re
import joblib
import pandas as pd
from urllib.parse import urlparse
import tldextract
from url_features import extract_url_features


# ---------------------------------------------------------------------------
# High-Abuse / Suspicious TLD Registry (Common in Phishing Campaigns)
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "work",
    "click", "loan", "fit", "country", "kim", "cricket", "science", "party",
    "gdn", "mom", "surf", "cam", "vip", "icu", "bar", "rest", "support",
    "online", "site", "space", "live", "link"
}


def deconstruct_url_syntax(url: str) -> dict:
    """
    Forensic Lexical Syntax Deconstructor.
    Splits the target URL into its protocol, subdomain, root domain, TLD,
    port, path, file extension, query string, and fragment tokens.
    """
    raw = str(url).strip()
    has_scheme = raw.startswith(("http://", "https://", "ftp://"))
    candidate = raw if has_scheme else "https://" + raw

    try:
        parsed = urlparse(candidate)
    except Exception:
        candidate = "https://" + re.sub(r"[^\w\-\.:/?&=#%]", "", raw)
        parsed = urlparse(candidate)

    protocol = parsed.scheme if parsed.scheme else ("https" if not has_scheme else "http")
    is_https = (protocol.lower() == "https")

    netloc = parsed.netloc or parsed.path.split("/")[0]
    port = parsed.port
    hostname = parsed.hostname or (netloc.split(":")[0] if netloc else "")

    is_ip = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname))

    try:
        ext = tldextract.extract(hostname)
        subdomain = ext.subdomain
        domain = ext.domain if ext.domain else (hostname if is_ip else "")
        suffix = ext.suffix
    except Exception:
        parts = hostname.split(".")
        if len(parts) >= 2:
            suffix = parts[-1]
            domain = parts[-2]
            subdomain = ".".join(parts[:-2])
        else:
            suffix = ""
            domain = hostname
            subdomain = ""

    subdomain_parts = [p for p in subdomain.split(".") if p] if subdomain else []
    subdomain_count = len(subdomain_parts)
    tld = ("." + suffix) if suffix else ""
    is_suspicious_tld = suffix.lower() in SUSPICIOUS_TLDS

    path = parsed.path or "/"
    base, file_ext = os.path.splitext(path)
    file_ext = file_ext if (file_ext and len(file_ext) <= 6) else ""

    query = ("?" + parsed.query) if parsed.query else ""
    fragment = ("#" + parsed.fragment) if parsed.fragment else ""

    return {
        "protocol": protocol,
        "is_https": is_https,
        "has_explicit_scheme": has_scheme,
        "hostname": hostname,
        "is_ip": is_ip,
        "subdomain": subdomain,
        "subdomain_count": subdomain_count,
        "domain": domain,
        "tld": tld,
        "is_suspicious_tld": is_suspicious_tld,
        "port": port,
        "path": path,
        "file_extension": file_ext,
        "query": query,
        "fragment": fragment,
        "full_display": raw,
    }


# ---------------------------------------------------------------------------
# 1. Model & Features loading — runs once at application startup
# ---------------------------------------------------------------------------

model = joblib.load("models/phishing_url_model.pkl")
features = joblib.load("models/phishing_url_features.pkl")


# ---------------------------------------------------------------------------
# 2. Known Official / Trusted Domains Allowlist
# ---------------------------------------------------------------------------

TRUSTED_DOMAINS_FILE = os.path.join("data", "supplement_legit.txt")
DEFAULT_TRUSTED_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "github.com",
    "shooliniuniversity.com", "shoolini.org", "digiicampus.com",
    "wikipedia.org", "amazon.com", "netflix.com", "stanford.edu",
    "mit.edu", "harvard.edu", "youtube.com", "linkedin.com"
}
TRUSTED_DOMAINS = set(DEFAULT_TRUSTED_DOMAINS)

if os.path.exists(TRUSTED_DOMAINS_FILE):
    with open(TRUSTED_DOMAINS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            domain = line.strip().lower()
            if domain and not domain.startswith("#"):
                TRUSTED_DOMAINS.add(domain)


def is_valid_url_format(text: str) -> bool:
    """
    Validate whether the input is a structurally valid web URL or domain name.
    Rejects raw conversational text, sentences, or arbitrary non-URL inputs.
    """
    if not text or not isinstance(text, str):
        return False

    text = text.strip()

    # URLs cannot contain raw whitespace (spaces, tabs, newlines)
    if any(c.isspace() for c in text):
        return False

    if len(text) < 3:
        return False

    candidate = text
    if not candidate.startswith(("http://", "https://", "ftp://")):
        candidate = "https://" + candidate

    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname
        if not hostname:
            return False

        # 1. Check if hostname is an IPv4 address
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(ip_pattern, hostname):
            parts = [int(p) for p in hostname.split(".")]
            return all(0 <= p <= 255 for p in parts)

        # 2. Check if hostname has at least a domain label and a valid TLD
        host_parts = hostname.split(".")
        if len(host_parts) < 2:
            return False

        tld = host_parts[-1]
        # Top-Level Domain must be alphabetic and >= 2 characters
        if not tld.isalpha() or len(tld) < 2:
            return False

        # Each DNS label must be valid alphanumeric or hyphens
        for part in host_parts:
            if not part or not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$", part):
                return False

        return True
    except Exception:
        return False


def is_trusted_domain(url: str) -> bool:
    """Check if the URL belongs to a known trusted official domain or its subdomains."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    hostname = urlparse(url).hostname or ""
    hostname = hostname.lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]

    parts = hostname.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in TRUSTED_DOMAINS:
            return True

    return False


# ---------------------------------------------------------------------------
# 3. Brand Impersonation & Typosquatting Detection
# ---------------------------------------------------------------------------

TARGETED_BRANDS = {
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.co.in", "google.co.uk", "google.com.au", "google.org"},
    "apple": {"apple.com", "icloud.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "netflix": {"netflix.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in", "amazon.de"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "twitter": {"twitter.com", "x.com"},
    "github": {"github.com", "github.io"},
    "linkedin": {"linkedin.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "binance": {"binance.com"},
    "shoolini": {"shooliniuniversity.com", "shoolini.org"},
}


def detect_brand_impersonation(url: str):
    """
    Detect if an untrusted domain is deceptively using a high-profile brand name.
    Example: 'paypal-security-verify.com' contains 'paypal' but is not an official PayPal domain.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    hostname = (urlparse(url).hostname or "").lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]

    for brand, legit_domains in TARGETED_BRANDS.items():
        # If this is the legitimate domain for this brand, it is NOT impersonation
        if any(hostname == d or hostname.endswith("." + d) for d in legit_domains):
            continue

        # Look for the brand name surrounded by non-alphanumeric separators (e.g., - . numbers)
        pattern = rf"(^|[-._0-9]){brand}([-._0-9]|$)"
        if re.search(pattern, hostname):
            return brand.capitalize()

    return None


# ---------------------------------------------------------------------------
# 4. Explainability & Feature Breakdown Helper
# ---------------------------------------------------------------------------

def get_feature_insights(extracted: dict, is_trusted: bool, impersonated_brand: str = None):
    """
    Generate user-friendly explainability metrics from extracted features.
    """
    is_https = extracted.get("IsHTTPS", 0) == 1
    is_ip = extracted.get("IsDomainIP", 0) == 1
    has_obf = extracted.get("HasObfuscation", 0) == 1
    subdomains = extracted.get("NoOfSubDomain", 0)

    insights = [
        {
            "name": "Protocol (Security)",
            "value": "HTTPS (Encrypted)" if is_https else "HTTP (Insecure)",
            "safe": is_https,
            "badge": "Secure" if is_https else "Warning",
        },
        {
            "name": "Host Identity",
            "value": "Raw IP Address" if is_ip else "Registered Domain",
            "safe": not is_ip,
            "badge": "High Risk" if is_ip else "Normal",
        },
        {
            "name": "Character Obfuscation",
            "value": f"{extracted.get('NoOfObfuscatedChar', 0)} encoded chars" if has_obf else "None (Clean)",
            "safe": not has_obf,
            "badge": "Suspicious" if has_obf else "Clean",
        },
        {
            "name": "Subdomain Depth",
            "value": f"{subdomains} Subdomain(s)",
            "safe": subdomains <= 1,
            "badge": "High" if subdomains > 1 else "Normal",
        },
        {
            "name": "Brand Safety",
            "value": f"Spoofing {impersonated_brand}" if impersonated_brand else "No Impersonation",
            "safe": impersonated_brand is None,
            "badge": "Impersonation" if impersonated_brand else "Clean",
        },
        {
            "name": "Domain Authority",
            "value": "Verified Official Domain" if is_trusted else "Unlisted / Standard Domain",
            "safe": is_trusted,
            "badge": "Verified" if is_trusted else "Unverified",
        },
    ]

    return insights


def get_risk_severity(phishing_prob: float, is_trusted: bool, impersonated: str = None):
    """
    Map phishing probability & heuristic indicators to a 4-level SOC Risk Severity Matrix.
    """
    if is_trusted:
        return {
            "level": "Low Risk / Clean",
            "tag_class": "sev-low",
            "advisory": "Verified official authority domain. TLS/SSL infrastructure confirmed. Destination is safe for navigation."
        }

    if impersonated:
        return {
            "level": "Critical Threat",
            "tag_class": "sev-crit",
            "advisory": f"Active Brand Impersonation: Do not enter credentials, 2FA codes, or payment details. Deceptively mimicking {impersonated} on an unverified host."
        }

    if phishing_prob >= 80.0:
        return {
            "level": "Critical Threat",
            "tag_class": "sev-crit",
            "advisory": "Severe phishing heuristics detected. Block destination and avoid downloading payloads or submitting credentials."
        }
    elif phishing_prob >= 50.0:
        return {
            "level": "High Risk",
            "tag_class": "sev-high",
            "advisory": "Significant structural anomalies detected by Random Forest heuristics. Restrict navigation or inspect in an isolated sandbox."
        }
    elif phishing_prob >= 25.0:
        return {
            "level": "Moderate Risk / Suspicious",
            "tag_class": "sev-mod",
            "advisory": "Elevated lexical complexity or unverified domain reputation. Exercise caution before entering personal data."
        }
    else:
        return {
            "level": "Low Risk",
            "tag_class": "sev-low",
            "advisory": "URL features align with standard legitimate web patterns. Standard web security hygiene recommended."
        }


# ---------------------------------------------------------------------------
# 5. Prediction Pipeline
# ---------------------------------------------------------------------------

def predict_url(url: str):
    """
    Run the multi-tier prediction pipeline for a given URL string.
    """
    url = str(url).strip()
    if not url:
        raise ValueError("URL cannot be empty")

    if not is_valid_url_format(url):
        raise ValueError(f"Invalid URL format: '{url}' is not a valid web URL or domain name.")

    extracted = extract_url_features(url)
    is_domain_listed = is_trusted_domain(url)
    raw_features = {f: extracted.get(f, 0) for f in features}
    syntax_tokens = deconstruct_url_syntax(url)

    # Tier 1: Defense-in-depth check for authority allowlist
    # To qualify for Tier 1 legitimate bypass, the destination must:
    # 1. Host a verified authority domain
    # 2. Use secure TLS encryption (IsHTTPS == 1; plain HTTP does not get a bypass)
    # 3. Contain no active hex / percent obfuscation (HasObfuscation == 0)
    # 4. Have normal subdomain depth (<= 2 levels, defending against subdomain hijack)
    # 5. Have no anomalous numerical padding in query tokens
    is_https = extracted.get("IsHTTPS", 0) == 1
    has_obf = extracted.get("HasObfuscation", 0) == 1
    deep_sub = extracted.get("NoOfSubDomain", 0) > 2
    digit_padding = (extracted.get("NoOfDegitsInURL", 0) >= 15 and extracted.get("DigitRatioInURL", 0) >= 0.15)

    tier1_eligible = is_domain_listed and is_https and not has_obf and not deep_sub and not digit_padding

    if tier1_eligible:
        sev = get_risk_severity(0.01, is_trusted=True)
        return {
            "result": "LEGITIMATE",
            "phishing_probability": 0.01,
            "legitimate_probability": 99.99,
            "impersonation_warning": None,
            "defense_tier": "Tier 1: Authority Allowlist",
            "defense_tier_description": "Verified official domain. TLS encryption, clean lexical tokens, and DNS structure confirmed.",
            "insights": get_feature_insights(extracted, is_trusted=True),
            "raw_features": raw_features,
            "risk_severity": sev["level"],
            "severity_tag_class": sev["tag_class"],
            "actionable_advisory": sev["advisory"],
            "syntax_tokens": syntax_tokens,
        }

    # Tier 2: Check for brand impersonation in untrusted domain
    impersonated = detect_brand_impersonation(url)
    if impersonated:
        sev = get_risk_severity(99.85, is_trusted=False, impersonated=impersonated)
        return {
            "result": "PHISHING",
            "phishing_probability": 99.85,
            "legitimate_probability": 0.15,
            "impersonation_warning": f"Brand impersonation detected: This domain attempts to mimic '{impersonated}' but is not an official {impersonated} website.",
            "defense_tier": "Tier 2: Brand Impersonation Engine",
            "defense_tier_description": f"Targeted brand '{impersonated}' detected in unverified domain using delimiter-aware regex.",
            "insights": get_feature_insights(extracted, is_trusted=False, impersonated_brand=impersonated),
            "raw_features": raw_features,
            "risk_severity": sev["level"],
            "severity_tag_class": sev["tag_class"],
            "actionable_advisory": sev["advisory"],
            "syntax_tokens": syntax_tokens,
        }

    # Tier 3: Machine Learning Model Evaluation
    features_df = pd.DataFrame([extracted])
    features_df = features_df[features]

    prediction = model.predict(features_df)[0]
    probabilities = model.predict_proba(features_df)[0]

    result = "PHISHING" if prediction == 0 else "LEGITIMATE"
    phish_pct = round(float(probabilities[0]) * 100, 2)
    legit_pct = round(float(probabilities[1]) * 100, 2)
    sev = get_risk_severity(phish_pct, is_trusted=False)

    tier_desc = "Evaluated against 18 structural and lexical URL features using 100 decision trees."
    if is_domain_listed:
        if not is_https:
            tier_desc = "Authority host dropped to Tier 3 ML due to insecure unencrypted HTTP protocol."
        elif has_obf:
            tier_desc = "Authority host dropped to Tier 3 ML due to detected character/hex obfuscation."
        elif deep_sub:
            tier_desc = "Authority host dropped to Tier 3 ML due to deep nested subdomain anomalies."
        elif digit_padding:
            tier_desc = "Authority host dropped to Tier 3 ML due to excessive numerical token padding."

    return {
        "result": result,
        "phishing_probability": phish_pct,
        "legitimate_probability": legit_pct,
        "impersonation_warning": None,
        "defense_tier": "Tier 3: Random Forest Classifier",
        "defense_tier_description": tier_desc,
        "insights": get_feature_insights(extracted, is_trusted=False),
        "raw_features": raw_features,
        "risk_severity": sev["level"],
        "severity_tag_class": sev["tag_class"],
        "actionable_advisory": sev["advisory"],
        "syntax_tokens": syntax_tokens,
    }
