# PhishGuard AI — Defense-in-Depth Cyber Threat Intelligence Platform

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.3-black.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.7.2-orange.svg?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![ML Architecture](https://img.shields.io/badge/Machine%20Learning-Strictly%20Classical%20(No%20DL)-success.svg)]()
[![Model Accuracy](https://img.shields.io/badge/Champion%20Accuracy-99.54%25-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An enterprise-grade cyber threat intelligence platform engineered to detect, deconstruct, and neutralize deceptive and malicious Uniform Resource Locators (URLs) in sub-millisecond real time.

Built on **Strictly Classical Machine Learning** (Random Forest, CART Decision Trees, Linear SVM, and Logistic Regression) with zero blackbox neural networks, featuring a **4-Tier Hybrid Defense-in-Depth** architecture, an **Adversarial Red-Team Simulator**, and live **Explainable AI (XAI)** factor decomposition.

---

## ⚡ Quick Execution Guide

Looking to quickly clone and run PhishGuard AI locally? Check out our dedicated guide:

👉 **[EXECUTION_GUIDE.md](EXECUTION_GUIDE.md)** — Step-by-step installation, virtual environment setup, training commands, and troubleshooting for Windows, macOS, and Linux.

### Quick Start (Terminal):
```bash
# 1. Clone the repository
git clone https://github.com/Aditya1112006/Phishing-Website-Detector.git
cd Phishing-Website-Detector

# 2. Setup virtual environment
python -m venv ml_env
# Windows: .\ml_env\Scripts\activate | macOS/Linux: source ml_env/bin/activate

# 3. Install requirements
pip install -r requirements.txt

# 4. Start the server
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser.

---

## 🛡️ Key System Architecture & Core Capabilities

PhishGuard AI eliminates single points of failure by replacing monolithic blackbox models with a layered defense-in-depth pipeline:

```
                          Target URL Ingestion
                                   │
                                   ▼
    ┌─────────────────────────────────────────────────────────────┐
    │  Tier 1: Zero-Latency Authority Allowlist                   │
    │  (Enforces TLS, no obfuscation, clean DNS token validation) │
    └──────────────┬──────────────────────────────┬───────────────┘
                   │ Valid TLS & Clean            │ Fails Sanity Check
                   ▼                              ▼
          [SAFE & LEGITIMATE]       ┌─────────────────────────────┐
             (0.01% Risk)           │  Tier 2: Brand Impersonation│
                                    │  & Typosquatting Engine     │
                                    └─────────────┬───────────────┘
                                                  │ Clean / Passed
                                                  ▼
                                    ┌─────────────────────────────┐
                                    │  Tier 3: Random Forest      │
                                    │  (100 Estimator Champion)   │
                                    └─────────────┬───────────────┘
                                                  │
                                                  ▼
                                    ┌─────────────────────────────┐
                                    │  Tier 4: Explainable AI     │
                                    │  (XAI Factor Decomposition) │
                                    └─────────────────────────────┘
```

### 1. Multi-Tier Defense Pipeline
- **Tier 1 — Authority Allowlist (0.01% Risk, < 0.1ms):** Verified institutional and commercial authorities (e.g., Google, GitHub, Microsoft, Shoolini University campus portals) with cryptographic TLS verification and subdomain sanity checks.
- **Tier 2 — Brand Impersonation Engine (99.85% Threat Risk):** Delimiter-aware regex scanner targeting 17 high-profile brands (PayPal, Netflix, Apple, Microsoft, Shoolini, etc.) that catches typosquatting and homoglyph attacks before the ML layer.
- **Tier 3 — 100-Tree Random Forest Ensemble (< 0.4ms Inference):** Champion classical ML classifier trained on 235,370 URLs with 18 extracted lexical, structural, and security signals.
- **Tier 4 — Explainable AI (XAI) & Lexical Deconstruction:** Full breakdown of protocol security, host resolution, TLD reputation, character obfuscation, and Gini feature contributions.

### 2. Adversarial Red-Team Simulator ("What-If" Studio)
An interactive penetration-testing suite allowing security researchers to test evasion techniques on real domains:
- 🔓 **Strip HTTPS / Downgrade HTTP:** Simulates unencrypted traffic and drops authority bypass to trigger ML alerts.
- 🎯 **Brand Typosquatting:** Injects deceptive brand tokens (`paypal-verify`, `shoolini-login`).
- 🌐 **Raw IP Address Host:** Bypasses DNS names with raw IP host representations (`192.168.1.104`).
- 🔏 **Hex / Percent Obfuscation:** Encodes characters to bypass simple pattern matching (`%20`, `%2E`).
- 🧩 **Deep Subdomain Hijack:** Synthesizes deceptive subdomains (`secure.login.verify...`).
- 🔍 **Query Entropy & Token Padding:** Appends deceptive tracking arguments.

### 3. Bulk Threat Feed Scanner & CSV Export
- Ingest hundreds of URLs simultaneously via multi-line text input or `.txt` batch upload.
- Color-coded batch threat metrics with instant CSV forensic report download.

---

## 📊 Classical Machine Learning Benchmarks

All models were rigorously trained and evaluated on an identical **80/20 stratified split** of the **PhiUSIIL Phishing Benchmark** (235,370 URLs: 100,520 phishing / 134,850 legitimate) using `train_comparative_models.py`:

| Algorithm / Model | Family | Accuracy | Precision | Recall | F1-Score | Latency | Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| ⭐ **Random Forest (100 Trees)** | Ensemble Bagging | **99.54%** | **99.39%** | **99.81%** | **99.60%** | **< 0.4ms** | **Selected Champion** |
| **Decision Tree (CART - Gini)** | Single Estimator | 97.80% | 97.20% | 98.10% | 97.65% | < 0.1ms | High Variance |
| **Linear SVM (Support Vector)** | Max-Margin Classifier | 91.40% | 90.80% | 92.10% | 91.45% | ~1.8ms | Linear Bound |
| **Logistic Regression (L2)** | Generalized Linear Model | 89.20% | 88.50% | 90.10% | 89.29% | < 0.2ms | High Bias |

### Mathematical Grounding: Why Random Forest Wins
Single Decision Trees suffer from high variance on small URL lexical shifts. Random Forest applies **Bootstrap Aggregation (Bagging)** and **Random Feature Subspace Splitting** ($m = \sqrt{18} \approx 4$).

Under the bias-variance decomposition:
$$\text{Var}(\bar{f}) = \rho\sigma^2 + \frac{1 - \rho}{M}\sigma^2$$

Subspace feature splitting drives tree correlation ($\rho \to 0$), minimizing total variance and achieving **99.54% accuracy** without inflating bias.

---

## 🔬 The 18 Live Extracted Feature Signals

Features are extracted directly from the raw URL string in `< 0.2ms` without fetching webpage contents or downloading external files:

| # | Feature Name | Description | Gini Importance |
|---|---|---|:---:|
| 1 | `IsHTTPS` | Protocol encryption state (1 for HTTPS, 0 for HTTP) | **40.2%** |
| 2 | `NoOfSubDomain` | Count of subdomain dot-delimiters | **11.5%** |
| 3 | `URLLength` | Total character count of full URL | **9.8%** |
| 4 | `TLDLength` | Length of top-level domain suffix | **7.4%** |
| 5 | `DomainLength` | Length of domain name excluding `www.` | **6.1%** |
| 6 | `NoOfDegitsInURL` | Count of numerical characters | **5.3%** |
| 7 | `DigitRatioInURL` | Proportion of digits to URL length | **4.7%** |
| 8 | `NoOfLettersInURL`| Count of alphabetic characters | **3.9%** |
| 9 | `LetterRatioInURL`| Proportion of alphabetic characters | **3.2%** |
| 10 | `NoOfHyphensInURL`| Count of hyphens (`-`) | **2.4%** |
| 11 | `NoOfDotsInURL` | Count of dots (`.`) | **1.9%** |
| 12 | `IsDomainIP` | Whether host is an IPv4 / IPv6 address | **1.1%** |
| 13 | `HasObfuscation` | Presence of percent-encoded hex sequences | **0.8%** |
| 14 | `NoOfObfuscatedChar` | Total count of percent-encoded entities | **0.5%** |
| 15 | `ObfuscationRatio` | Ratio of encoded entities to URL length | **0.4%** |
| 16 | `NoOfEqualsInURL` | Count of `=` characters (query parameters) | **0.4%** |
| 17 | `NoOfQMarkInURL` | Count of `?` characters (query string entry) | **0.3%** |
| 18 | `NoOfAmpersandInURL` | Count of `&` characters (query argument chaining) | **0.1%** |

---

## 🔌 Programmatic REST API

Integrate PhishGuard AI into automated firewalls, browser extensions, or SIEM pipelines:

### Endpoint: `POST /api/predict`

**Request:**
```bash
curl -X POST http://127.0.0.1:5000/api/predict \
     -H "Content-Type: application/json" \
     -d '{"url": "https://paypal-security-account.com/login"}'
```

**Response:**
```json
{
  "status": "success",
  "url": "https://paypal-security-account.com/login",
  "prediction": "PHISHING",
  "is_phishing": true,
  "confidence_percentage": 99.85,
  "risk_score": 99.85,
  "defense_tier": "Tier 2: Brand Impersonation Engine",
  "verdict_reason": "High-risk brand spoofing detected: Domain embeds targeted brand 'paypal' with deceptive delimiters.",
  "phishing_probability": 0.9985,
  "legitimate_probability": 0.0015
}
```

---

## 📁 Repository Structure

```text
Phishing-Website-Detector/
├── app.py                         # Flask application & web / API routes
├── config.py                      # Centralized environment configuration (.env loader)
├── predictor.py                   # 4-Tier Hybrid Defense-in-Depth Pipeline
├── url_features.py                # 18-Signal Structural & Lexical Feature Extractor
├── train_comparative_models.py    # Multi-model training, benchmarking & audit generator
├── retrain.py                     # Champion Random Forest training script
├── requirements.txt               # Pinned dependencies
├── .env.example                   # Environment variable template
├── .gitignore                     # Git exclusion rules
├── EXECUTION_GUIDE.md             # Complete step-by-step setup guide
├── README.md                      # Platform documentation & overview
├── LICENSE                        # MIT License
│
├── scripts/
│   └── debug_url.py               # Forensic CLI URL debugging script
│
├── tests/
│   └── test_pipeline.py           # Automated unit & integration test suite
│
├── static/
│   └── style.css                  # Obsidian glassmorphic UI styling
│
├── templates/
│   └── index.html                 # Main web command center interface
│
└── models/                        # Serialized models & benchmark proof
    ├── phishing_url_model.pkl     # Deployed Random Forest Champion (100 Trees)
    ├── decision_tree_model.pkl    # CART Decision Tree
    ├── linear_svm_model.pkl       # Linear Support Vector Classifier
    ├── logistic_regression_model.pkl # Generalized Linear Classifier
    ├── training_benchmark_proof.txt # Formatted viva proof report
    └── model_comparison_benchmark.json # JSON benchmark data
```

---

## 📜 License

This project is licensed under the terms of the [MIT License](LICENSE).
