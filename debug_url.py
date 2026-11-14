"""
debug_url.py
------------
Quick diagnostic tool. Shows every feature value extracted from a URL
and the model's prediction + probabilities.

Usage:
    python debug_url.py "https://www.google.com"
    python debug_url.py "https://chat.openai.com"
"""

import sys
from url_features import extract_url_features, LIVE_FEATURES
from predictor import predict_url

if len(sys.argv) < 2:
    print("Usage: python debug_url.py \"<url>\"")
    sys.exit(1)

url = sys.argv[1]
print(f"\nURL: {url}")
print("=" * 55)

features = extract_url_features(url)

KEY_FEATURES = ("DomainLength", "IsHTTPS", "NoOfDegitsInURL", "LetterRatioInURL")

print(f"{'Feature':<25} {'Value':>10}")
print("-" * 55)
for feat in LIVE_FEATURES:
    marker = "  >> KEY" if feat in KEY_FEATURES else ""
    print(f"{feat:<25} {features[feat]:>10.4f}{marker}")

print("=" * 55)

result = predict_url(url)
print(f"\nPrediction    : {result['result']}")
print(f"Phishing      : {result['phishing_probability']}%")
print(f"Legitimate    : {result['legitimate_probability']}%")
print()
