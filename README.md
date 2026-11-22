# PhishGuard AI

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.3-000000.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.7.2-F7931E.svg?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![Classical ML](https://img.shields.io/badge/ML%20Architecture-Classical%20(No%20Deep%20Learning)-2ea44f.svg)]()
[![Model Accuracy](https://img.shields.io/badge/Held--Out%20Accuracy-99.57%25-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

PhishGuard AI is a real-time phishing URL detection engine and security analyst console built with Python, scikit-learn, and Flask. 

Rather than downloading webpage HTML or executing untrusted JavaScript (which poses infection risks and introduces several seconds of latency), PhishGuard inspects the **lexical structure, character statistics, and protocol properties** of URLs directly. It reaches classification verdicts in **under 1 millisecond** on standard CPU hardware.

---

## Table of Contents
- [Why URL-Only Analysis?](#why-url-only-analysis)
- [How It Works (The 4-Tier Defense Pipeline)](#how-it-works-the-4-tier-defense-pipeline)
- [Quick Start](#quick-start)
- [Interactive Features](#interactive-features)
- [Model Performance & Comparative Benchmarks](#model-performance--comparative-benchmarks)
- [Feature Engineering (The 18 Signals)](#feature-engineering-the-18-signals)
- [REST API Reference](#rest-api-reference)
- [Running Automated Tests](#running-automated-tests)
- [Project Structure](#project-structure)
- [Real-World Limitations](#real-world-limitations)
- [License](#license)

---

## Why URL-Only Analysis?

Most commercial web crawlers fetch full page contents, evaluate DOM trees, and inspect certificate chains. While effective, that approach has trade-offs:
1. **Network latency:** Fetching third-party websites takes 1 to 5 seconds per URL.
2. **Security hazard:** Crawling unknown malicious hosts can trigger drive-by downloads or expose crawler infrastructure.
3. **Ephemeral attacks:** Phishing sites frequently cloaking against crawlers (serving 404s to known security bots while serving phishing forms to victims).

PhishGuard AI analyzes the syntax of the link itself. Attackers leave structural footprints when disguising URLs—such as excessive token length, hex-encoded bytes (`%20`, `%2E`), deep subdomain chains, brand names glued to hyphens, or unencrypted HTTP links. Classical machine learning recognizes these tabular patterns in less than a millisecond.

---

## How It Works (The 4-Tier Defense Pipeline)

A common pitfall with pure machine learning on security data is **shortcut learning** (for example, models learning that "any link with multiple slashes is malicious" because the training set contained mostly top-level legitimate domains). To eliminate false positives on deep legitimate links while maintaining strict defense against adversarial evasion, PhishGuard uses a **4-tier hybrid pipeline**:

```text
                           Incoming URL
                                │
                                ▼
    ┌─────────────────────────────────────────────────────────┐
    │  Tier 1: Authority Allowlist Integrity Check            │
    │  • Matches verified domains (Google, Wikipedia, etc.)   │
    │  • Requires HTTPS, normal subdomains, zero obfuscation  │
    └──────────────┬──────────────────────────┬───────────────┘
                   │ Pass                     │ Fails sanity check (e.g., HTTP downgrade)
                   ▼                          ▼
       [Likely Legitimate]       ┌────────────────────────────┐
           (0.01% Risk)          │ Tier 2: Brand Engine       │
                                 │ • Regex scans 17 brands    │
                                 │ • Catches delimiter spoofing│
                                 └────────────┬───────────────┘
                                              │ Clean (no spoof)
                                              ▼
                                 ┌────────────────────────────┐
                                 │ Tier 3: Random Forest ML   │
                                 │ • 100 Bagged Trees         │
                                 │ • 18 live extracted features│
                                 └────────────┬───────────────┘
                                              │
                                              ▼
                                 ┌────────────────────────────┐
                                 │ Tier 4: Explainable AI     │
                                 │ • Token breakdown & factors│
                                 └────────────────────────────┘
```

1. **Tier 1 — Authority Allowlist & Sanity Check:** Verified domains (Google, Wikipedia, educational portals) pass with `0.01%` risk in `< 0.1ms`. Crucially, an allowlisted domain **only** bypasses ML if it passes cryptographic checks: it must use secure HTTPS, have no hex obfuscation, and have no abnormal subdomain nesting. If someone types `http://www.google.com` or `google.com%2Eevil.com`, it drops immediately to Tier 3.
2. **Tier 2 — Brand Impersonation Engine:** Catches deliberate typosquatting and brand phishing before machine learning. Pre-compiled regular expressions scan for high-value targets (PayPal, Netflix, Apple, Microsoft, Amazon, etc.) surrounded by delimiters like `paypal-security-login.com` or `netflix-billing-update.org`, issuing a `99.85%` threat verdict.
3. **Tier 3 — Random Forest Ensemble:** Evaluates general and unlisted URLs using 100 bagged decision trees trained on 235,370 URLs.
4. **Tier 4 — Explainable AI (XAI) & Lexical Deconstruction:** Deconstructs the URL into scheme, domain, TLD, path, parameters, and flags potential security risks (insecure protocol, raw IP, high digit ratio) so the user understands the rationale behind the verdict.

---

## Quick Start

### Prerequisites
- Python 3.10 or higher
- Git

### 1. Clone the repository
```bash
git clone https://github.com/Aditya1112006/Phishing-Website-Detector.git
cd Phishing-Website-Detector
```

### 2. Create and activate a virtual environment
```bash
# On Windows (PowerShell)
python -m venv ml_env
.\ml_env\Scripts\activate

# On macOS / Linux
python3 -m venv ml_env
source ml_env/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment (Optional)
The project includes sensible defaults, but you can configure local parameters:
```bash
cp .env.example .env
```

### 5. Launch the application
```bash
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser.

> For troubleshooting and detailed operating system guides, read **[EXECUTION_GUIDE.md](EXECUTION_GUIDE.md)**.

---

## Interactive Features

The application runs an obsidian-themed web console with three primary tools:

### 1. Single Target URL Scanner
- Paste any link or domain name to run a multi-tier threat evaluation.
- Displays risk severity badge, calculated probability split, active defense layer, and a full lexical token breakdown.
- Clickable preset buttons let you test real-world legitimate and malicious links with one click.

### 2. Adversarial Red-Team Simulator ("What-If" Studio)
Test how defensive layers respond to active evasion techniques:
- Pick a clean baseline domain (e.g., `paypal.com`, `google.com`).
- Toggle individual attack vectors:
  - **Strip HTTPS:** Downgrades protocol to insecure `http://`.
  - **Brand Typosquatting:** Injects targeted brand tokens.
  - **Raw IP Host:** Replaces domain name with raw IP address.
  - **Hex Obfuscation:** Encodes dots or slashes with percent notation (`%20`, `%2E`).
  - **Deep Subdomains:** Appends multi-level subdomains (`secure.login.verify...`).
  - **Query Padding:** Adds high-entropy token strings.
- Watch the synthesized URL, triggered defense tier, and probability shift in real time.

### 3. Bulk Threat Feed Scanner & CSV Export
- Ingest and scan up to 25 URLs simultaneously.
- Color-coded results identify `LEGITIMATE`, `PHISHING`, and invalid plain-text strings.
- Export findings into a downloadable `.csv` audit report for incident response documentation.

---

## Model Performance & Comparative Benchmarks

All models were trained and tested on an identical 80/20 stratified split of the **PhiUSIIL Phishing Dataset** (235,370 unique URLs: 100,520 phishing / 134,850 legitimate):

| Algorithm / Model | Model Family | Accuracy | Precision | Recall | F1-Score | Inference Latency | Finding / Rationale |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| ⭐ **Random Forest (100 Trees)** | **Ensemble Bagging** | **99.57%** | **99.20%** | **99.81%** | **99.50%** | **0.60 ms** | **Selected Champion.** Optimal bias-variance trade-off through subspace feature decorrelation. |
| **Decision Tree (CART - Gini)** | Single Tree | 97.80% | 97.20% | 98.10% | 97.65% | 0.08 ms | **High Variance.** Prone to over-reacting to small lexical shifts without ensemble voting. |
| **Linear SVM** | Max-Margin | 91.40% | 90.80% | 92.10% | 91.45% | 1.80 ms | **Linear Bound.** Underfits non-linear feature conjunctions (e.g., digit density + protocol). |
| **Logistic Regression (L2)** | Generalized Linear | 89.20% | 88.50% | 90.10% | 89.29% | 0.15 ms | **High Bias.** Struggles when individual features are ambiguous but malicious in combination. |

### Why Classical ML Over Deep Learning?
In many academic circles, deep learning is often applied by default. For URL classification, classical tree ensembles are deliberately superior:
- **Zero GPU Overhead:** Runs anywhere—on lightweight firewall micro-instances, router gateways, or laptop CPUs.
- **Explainability:** Feature splits can be audited with exact Gini impurity metrics rather than blackbox neural activations.
- **Tabular Data Efficiency:** Random Forest consistently outperforms deep neural networks on structured numerical feature tables.

---

## Feature Engineering (The 18 Signals)

Features are computed using standard Python string and URL parsing operations in **`~0.013 ms`**:

| # | Feature | Description | Gini Importance |
|---|---|---|:---:|
| 1 | `IsHTTPS` | Whether URL uses TLS encryption (`1` for HTTPS, `0` for HTTP) | **40.2%** |
| 2 | `NoOfSubDomain` | Number of dot-separated subdomain labels | **11.5%** |
| 3 | `URLLength` | Total character length of full URL | **9.8%** |
| 4 | `TLDLength` | Length of top-level domain string | **7.4%** |
| 5 | `DomainLength` | Length of registered domain name | **6.1%** |
| 6 | `NoOfDegitsInURL` | Count of numeric digits | **5.3%** |
| 7 | `DigitRatioInURL` | Ratio of digits to total URL length | **4.7%** |
| 8 | `NoOfLettersInURL`| Count of alphabetic characters | **3.9%** |
| 9 | `LetterRatioInURL`| Ratio of letters to total URL length | **3.2%** |
| 10 | `NoOfHyphensInURL`| Count of `-` characters | **2.4%** |
| 11 | `NoOfDotsInURL` | Count of `.` characters | **1.9%** |
| 12 | `IsDomainIP` | Binary flag if host is an IPv4 or IPv6 address | **1.1%** |
| 13 | `HasObfuscation` | Binary flag for percent-encoded hex sequences | **0.8%** |
| 14 | `NoOfObfuscatedChar` | Total count of `%xx` entities | **0.5%** |
| 15 | `ObfuscationRatio` | Ratio of encoded entities to URL length | **0.4%** |
| 16 | `NoOfEqualsInURL` | Count of `=` query characters | **0.4%** |
| 17 | `NoOfQMarkInURL` | Count of `?` parameter markers | **0.3%** |
| 18 | `NoOfAmpersandInURL` | Count of `&` query argument delimiters | **0.1%** |

---

## REST API Reference

PhishGuard includes JSON REST endpoints for SIEM pipelines, browser extensions, or command-line scripts.

### 1. Healthcheck
```bash
curl http://127.0.0.1:5000/api/health
```
```json
{
  "status": "healthy",
  "service": "PhishGuard AI Threat Intelligence",
  "model_loaded": true,
  "defense_architecture": "4-Tier Hybrid Pipeline"
}
```

### 2. Predict Single URL
```bash
curl -X POST http://127.0.0.1:5000/api/predict \
     -H "Content-Type: application/json" \
     -d '{"url": "https://paypal-security-center.com/login"}'
```
```json
{
  "status": "success",
  "url": "https://paypal-security-center.com/login",
  "result": "PHISHING",
  "phishing_probability": 99.85,
  "legitimate_probability": 0.15,
  "defense_tier": "Tier 2: Brand Impersonation Engine",
  "impersonation_warning": "Brand impersonation detected: This domain attempts to mimic 'Paypal' but is not an official Paypal website.",
  "risk_severity": "Critical Threat"
}
```

### 3. Batch Predict Multiple URLs
```bash
curl -X POST http://127.0.0.1:5000/api/batch_predict \
     -H "Content-Type: application/json" \
     -d '{"urls": ["https://google.com", "random text input", "https://netflix-billing-update.org"]}'
```
```json
{
  "status": "success",
  "count": 3,
  "results": [
    {
      "url": "https://google.com",
      "result": "LEGITIMATE",
      "defense_tier": "Tier 1: Authority Allowlist",
      "phishing_probability": 0.01
    },
    {
      "url": "random text input",
      "result": "INVALID",
      "defense_tier": "Format Validation",
      "inspection_notes": "Plain Text",
      "phishing_probability": null
    },
    {
      "url": "https://netflix-billing-update.org",
      "result": "PHISHING",
      "defense_tier": "Tier 2: Brand Impersonation Engine",
      "phishing_probability": 99.85
    }
  ]
}
```

---

## Running Automated Tests

The test suite covers normal domains, invalid strings, edge cases (IPv4, IPv6, port numbers, trailing dots), latency benchmarks, and Flask API routes.

Execute all unit and integration tests:
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

Run CLI forensic diagnostic on any URL:
```bash
python scripts/debug_url.py "https://example.com"
```

Re-train comparative models and generate live benchmark audit files:
```bash
python train_comparative_models.py
```

---

## Project Structure

```text
Phishing-Website-Detector/
├── app.py                         # Flask web application & REST API routes
├── config.py                      # Centralized environment configuration (.env loader)
├── predictor.py                   # 4-Tier Hybrid Defense-in-Depth pipeline
├── url_features.py                # 18-signal structural & lexical feature extractor
├── train_comparative_models.py    # Multi-model training, benchmarking & audit generator
├── retrain.py                     # Standalone Random Forest training script
├── requirements.txt               # Pinned Python package dependencies
├── .env.example                   # Environment configuration template
├── .gitignore                     # Git exclusion rules
├── EXECUTION_GUIDE.md             # Detailed installation and setup guide
├── README.md                      # Primary project documentation
├── LICENSE                        # MIT License
│
├── scripts/
│   └── debug_url.py               # Forensic CLI tool to inspect individual URLs
│
├── tests/
│   └── test_pipeline.py           # Comprehensive automated test suite (25 test cases)
│
├── static/
│   └── style.css                  # Obsidian glassmorphic styling
│
├── templates/
│   └── index.html                 # Web dashboard interface (Jinja2)
│
└── models/                        # Serialized ML models & benchmark logs (generated)
    ├── phishing_url_model.pkl     # Deployed Random Forest model (22.8 MB)
    ├── decision_tree_model.pkl    # CART Decision Tree model (28.3 KB)
    ├── linear_svm_model.pkl       # Support Vector Classifier (1.4 KB)
    ├── logistic_regression_model.pkl # Generalized Linear Classifier (1.5 KB)
    ├── training_benchmark_proof.txt  # Human-readable benchmark report
    └── model_comparison_benchmark.json # Machine-readable metrics
```

---

## Real-World Limitations

Being transparent about model boundaries is essential in cybersecurity:
- **No DOM / Content Inspection:** PhishGuard analyzes URLs, not page HTML. A compromised legitimate site hosting a phishing form under a clean URL cannot be detected by lexical features alone.
- **Shortener Masking:** URL shorteners (`bit.ly`, `tinyurl.com`) hide the real destination. In a production pipeline, this engine should be paired with an HTTP redirect unshortener.
- **Zero-Day Top-Level Domains:** Brand imitation on newly registered obscure TLDs is detected by Tier 2, but novel brands outside our dictionary rely solely on Tier 3 ML.

---

## License

This project is open-source software licensed under the terms of the [MIT License](LICENSE).
