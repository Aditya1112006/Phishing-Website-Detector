import joblib
import pandas as pd
from urllib.parse import urlparse
import re
import ipaddress


# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------

model = joblib.load("models/phishing_url_model.pkl")
features = joblib.load("models/phishing_url_features.pkl")


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_url_features(url):
    """
    Extract the 13 URL-based structural features used by the deployed model.

    The extractor prepends 'https://' internally for parsing if no scheme is
    present, but URLLength is always based on the original stripped input.

    Returns a dict with 14 keys (including IsHTTPS). The prediction pipeline
    selects only the 13 features used during training.
    """
    url = str(url).strip()

    if not url:
        raise ValueError("URL cannot be empty")

    if not url.startswith(("http://", "https://")):
        url_for_parse = "https://" + url
    else:
        url_for_parse = url

    parsed = urlparse(url_for_parse)
    hostname = parsed.hostname or ""

    # Strip leading www. before measuring domain length
    domain = hostname
    if domain.startswith("www."):
        domain = domain[4:]

    domain_length = len(domain)

    # Detect raw IP addresses as hostnames
    try:
        ipaddress.ip_address(hostname)
        is_domain_ip = 1
    except ValueError:
        is_domain_ip = 0

    # TLD length
    if "." in hostname:
        tld_length = len(hostname.split(".")[-1])
    else:
        tld_length = 0

    # Subdomain count (simplified: parts beyond domain + TLD)
    hostname_parts = hostname.split(".")
    no_subdomain = len(hostname_parts) - 2 if len(hostname_parts) >= 3 else 0

    # Percent-encoded (obfuscated) characters
    obfuscated_chars = re.findall(r"%[0-9a-fA-F]{2}", url)
    no_obfuscated_char = len(obfuscated_chars)
    has_obfuscation = 1 if no_obfuscated_char > 0 else 0
    obfuscation_ratio = no_obfuscated_char / len(url) if len(url) > 0 else 0

    # Character counts
    no_letters = sum(c.isalpha() for c in url)
    no_digits = sum(c.isdigit() for c in url)
    no_equals = url.count("=")
    no_qmark = url.count("?")
    no_ampersand = url.count("&")

    return {
        "URLLength": len(url),
        "DomainLength": domain_length,
        "IsDomainIP": is_domain_ip,
        "TLDLength": tld_length,
        "NoOfSubDomain": no_subdomain,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": no_obfuscated_char,
        "ObfuscationRatio": obfuscation_ratio,
        "NoOfLettersInURL": no_letters,
        "NoOfDegitsInURL": no_digits,
        "NoOfEqualsInURL": no_equals,
        "NoOfQMarkInURL": no_qmark,
        "NoOfAmpersandInURL": no_ampersand,
        "IsHTTPS": 1 if parsed.scheme.lower() == "https" else 0,
    }


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

def predict_url(url):
    """
    Run the full prediction pipeline for a given URL string.

    Returns a dict:
        {
            "result": "PHISHING" | "LEGITIMATE",
            "phishing_probability": float (0–100, rounded to 2dp),
            "legitimate_probability": float (0–100, rounded to 2dp),
        }

    Raises ValueError for empty input.
    Raises any exception from the extractor or model as-is
    (caller is responsible for catching).
    """
    extracted = extract_url_features(url)

    features_df = pd.DataFrame([extracted])
    features_df = features_df[features]  # select the 13 model features in order

    prediction = model.predict(features_df)[0]
    probabilities = model.predict_proba(features_df)[0]

    result = "PHISHING" if prediction == 0 else "LEGITIMATE"

    return {
        "result": result,
        "phishing_probability": round(probabilities[0] * 100, 2),
        "legitimate_probability": round(probabilities[1] * 100, 2),
    }
