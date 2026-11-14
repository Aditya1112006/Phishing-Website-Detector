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
from url_features import extract_url_features


# ---------------------------------------------------------------------------
# 1. Model & Features loading — runs once at application startup
# ---------------------------------------------------------------------------

model = joblib.load("models/phishing_url_model.pkl")
features = joblib.load("models/phishing_url_features.pkl")


# ---------------------------------------------------------------------------
# 2. Known Official / Trusted Domains Allowlist
# ---------------------------------------------------------------------------

TRUSTED_DOMAINS_FILE = os.path.join("data", "supplement_legit.txt")
TRUSTED_DOMAINS = set()

if os.path.exists(TRUSTED_DOMAINS_FILE):
    with open(TRUSTED_DOMAINS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            domain = line.strip().lower()
            if domain and not domain.startswith("#"):
                TRUSTED_DOMAINS.add(domain)


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

    extracted = extract_url_features(url)
    trusted = is_trusted_domain(url)

    # Tier 1: Check known official / reputable domain
    if trusted:
        return {
            "result": "LEGITIMATE",
            "phishing_probability": 0.01,
            "legitimate_probability": 99.99,
            "impersonation_warning": None,
            "insights": get_feature_insights(extracted, is_trusted=True),
        }

    # Tier 2: Check for brand impersonation in untrusted domain
    impersonated = detect_brand_impersonation(url)
    if impersonated:
        return {
            "result": "PHISHING",
            "phishing_probability": 99.85,
            "legitimate_probability": 0.15,
            "impersonation_warning": f"Brand impersonation detected: This domain attempts to mimic '{impersonated}' but is not an official {impersonated} website.",
            "insights": get_feature_insights(extracted, is_trusted=False, impersonated_brand=impersonated),
        }

    # Tier 3: Machine Learning Model Evaluation
    features_df = pd.DataFrame([extracted])
    features_df = features_df[features]

    prediction = model.predict(features_df)[0]
    probabilities = model.predict_proba(features_df)[0]

    result = "PHISHING" if prediction == 0 else "LEGITIMATE"

    return {
        "result": result,
        "phishing_probability": round(float(probabilities[0]) * 100, 2),
        "legitimate_probability": round(float(probabilities[1]) * 100, 2),
        "impersonation_warning": None,
        "insights": get_feature_insights(extracted, is_trusted=False),
    }
