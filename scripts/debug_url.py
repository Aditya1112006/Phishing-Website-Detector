"""
scripts/debug_url.py
--------------------
Command-line diagnostic utility for PhishGuard AI.
Extracts all 18 structural & lexical features from a target URL and
executes the 4-tier defense pipeline.

Usage:
    python scripts/debug_url.py "https://example.com"
"""

import sys
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from url_features import extract_url_features, LIVE_FEATURES
from predictor import predict_url, is_valid_url_format


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/debug_url.py \"<url>\"")
        sys.exit(1)

    url = sys.argv[1].strip()
    print(f"\nTarget URL: {url}")
    print("=" * 60)

    if not is_valid_url_format(url):
        print("[-] Error: Input is plain text or an invalid URL structure.")
        sys.exit(1)

    features = extract_url_features(url)
    key_features = {"IsHTTPS", "DomainLength", "NoOfSubDomain", "URLLength", "IsDomainIP"}

    print(f"{'Feature Name':<28} {'Extracted Value':>12}")
    print("-" * 60)
    for feat in LIVE_FEATURES:
        val = features.get(feat, 0)
        marker = "  [KEY SIGNAL]" if feat in key_features else ""
        if isinstance(val, float):
            print(f"{feat:<28} {val:>12.4f}{marker}")
        else:
            print(f"{feat:<28} {val:>12}{marker}")

    print("=" * 60)

    res = predict_url(url)
    print(f"Defense Tier  : {res.get('defense_tier')}")
    print(f"Final Verdict : {res.get('result')}")
    print(f"Phishing Risk : {res.get('phishing_probability')}%")
    print(f"Legitimate    : {res.get('legitimate_probability')}%")
    print(f"Risk Severity : {res.get('risk_severity')}")
    if res.get("impersonation_warning"):
        print(f"Advisory      : {res.get('impersonation_warning')}")
    print()


if __name__ == "__main__":
    main()
