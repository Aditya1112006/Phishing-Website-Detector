from flask import Flask, request, render_template
import joblib
from urllib.parse import urlparse
import re
import ipaddress
import pandas as pd

app = Flask(__name__)

# Load trained model and feature list
model = joblib.load("models/phishing_url_model.pkl")
features = joblib.load("models/phishing_url_features.pkl")


def extract_url_features(url):
    url = str(url).strip()

    if not url:
        raise ValueError("URL cannot be empty")

    if not url.startswith(("http://", "https://")):
        url_for_parse = "https://" + url
    else:
        url_for_parse = url

    parsed = urlparse(url_for_parse)
    hostname = parsed.hostname or ""

    domain = hostname

    if domain.startswith("www."):
        domain = domain[4:]

    domain_length = len(domain)

    try:
        ipaddress.ip_address(hostname)
        is_domain_ip = 1
    except ValueError:
        is_domain_ip = 0

    if "." in hostname:
        tld = hostname.split(".")[-1]
        tld_length = len(tld)
    else:
        tld_length = 0

    hostname_parts = hostname.split(".")

    no_subdomain = (
        len(hostname_parts) - 2
        if len(hostname_parts) >= 3
        else 0
    )

    obfuscated_chars = re.findall(
        r"%[0-9a-fA-F]{2}",
        url
    )

    no_obfuscated_char = len(obfuscated_chars)

    has_obfuscation = (
        1 if no_obfuscated_char > 0 else 0
    )

    obfuscation_ratio = (
        no_obfuscated_char / len(url)
        if len(url) > 0
        else 0
    )

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
        "IsHTTPS": 1 if parsed.scheme.lower() == "https" else 0
    }

@app.route("/predict", methods=["POST"])
def predict():
    url = request.form["url"]

    # Extract URL features
    extracted_features = extract_url_features(url)

    # Convert to DataFrame
    features_df = pd.DataFrame([extracted_features])

    # Keep only the 13 features used by the model
    features_df = features_df[features]

    # Make prediction
    prediction = model.predict(features_df)[0]

    # Get probabilities
    probabilities = model.predict_proba(features_df)[0]

    phishing_probability = probabilities[0]
    legitimate_probability = probabilities[1]

    if prediction == 0:
        result = "PHISHING"
    else:
        result = "LEGITIMATE"

    return render_template(
        "index.html",
        url=url,
        result=result,
        phishing_probability=round(phishing_probability * 100, 2),
        legitimate_probability=round(legitimate_probability * 100, 2)
    )


@app.route("/")
def home():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)