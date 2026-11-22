# PhishGuard AI — Complete Execution & Setup Guide

This guide provides end-to-end instructions for setting up, training, running, and testing the **PhishGuard AI** cyber threat intelligence platform on any machine (Windows, macOS, or Linux).

---

## 📋 System Prerequisites

Before starting, ensure your system meets the following requirements:
- **Operating System:** Windows 10/11, macOS 12+, or Ubuntu/Debian/Linux.
- **Python Version:** Python **3.10** or higher (Recommended: Python 3.10 or 3.11).
- **Package Manager:** `pip` (Python package manager).
- **Version Control:** `git`.
- **Memory & Storage:** 2 GB+ RAM, ~200 MB disk space (or ~300 MB if storing the full PhiUSIIL dataset).

---

## 🚀 Quick Start (In 4 Steps)

### Step 1: Clone the Repository

Open your terminal or command prompt and clone the repository:

```bash
git clone https://github.com/Aditya1112006/Phishing-Website-Detector.git
cd Phishing-Website-Detector
```

---

### Step 2: Create & Activate a Virtual Environment

Isolating dependencies inside a virtual environment prevents conflicts with system packages.

#### On Windows (PowerShell):
```powershell
python -m venv ml_env
.\ml_env\Scripts\Activate.ps1
```
> *Tip: If PowerShell displays an `Execution_Policies` script error, run:*
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> .\ml_env\Scripts\Activate.ps1
> ```

#### On Windows (Command Prompt - CMD):
```cmd
python -m venv ml_env
ml_env\Scripts\activate.bat
```

#### On macOS / Linux:
```bash
python3 -m venv ml_env
source ml_env/bin/activate
```

---

### Step 3: Install Required Dependencies

Install the pinned dependencies from `requirements.txt`:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### Installed Packages:
- `Flask==3.1.3` (Web application server)
- `scikit-learn==1.7.2` (Classical Machine Learning algorithms)
- `pandas==2.3.3` & `numpy==2.2.6` (Data manipulation & feature vector arrays)
- `joblib==1.5.3` (Model serialization & binary loading)
- `Jinja2==3.1.6` & `Werkzeug==3.1.9` (Templating & routing utilities)

---

### Step 4: Run the Web Application

Start the local Flask development server:

```bash
python app.py
```

You will see output similar to:
```text
 * Serving Flask app 'app'
 * Debug mode: off
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
```

Open your browser and navigate to:
👉 **`http://127.0.0.1:5000`**

---

## 🧠 Machine Learning Models & Comparative Training

PhishGuard AI uses **Strictly Classical Machine Learning** (Random Forest, Decision Tree, Linear SVM, Logistic Regression) with zero blackbox neural networks.

### Running Comparative Model Training
To train all classical models, evaluate their metrics, and generate live benchmark audit files:

```bash
python train_comparative_models.py
```

This script executes in **~4 seconds** on CPU and outputs:
```text
======================================================================================
Model Name                     Accuracy   Precision   Recall     F1-Score   Latency    Status
--------------------------------------------------------------------------------------
⭐ Random Forest (100 Trees)    99.54 %    99.39 %     99.81 %    99.60 %    < 0.4ms    Selected Champion
Decision Tree (CART - Gini)    97.80 %    97.20 %     98.10 %    97.65 %    < 0.1ms    High Variance
Linear SVM (Support Vector)    91.40 %    90.80 %     92.10 %    91.45 %    ~1.8ms     Linear Bound
Logistic Regression (L2)       89.20 %    88.50 %     90.10 %    89.29 %    < 0.2ms    High Bias
======================================================================================
```

The generated serialized models are saved in `models/`:
- `models/phishing_url_model.pkl` (22.8 MB Random Forest Champion)
- `models/decision_tree_model.pkl` (28.3 KB CART Decision Tree)
- `models/linear_svm_model.pkl` (1.4 KB Linear SVM)
- `models/logistic_regression_model.pkl` (1.5 KB Logistic Regression)
- `models/training_benchmark_proof.txt` (Live audit report)
- `models/model_comparison_benchmark.json` (Machine-readable benchmark)

---

## 🛡️ Interactive Features & Navigation

Once `http://127.0.0.1:5000` is open:

### 1. Interactive Single URL Scanner
- Enter any URL in the search bar (e.g. `https://login.shooliniuniversity.com/feed` or `https://paypal-security-account.com/login`).
- Click **Analyze Target**.
- View the 4-Tier Defense Execution Route, Threat Risk Score, and SOC Advisory.

### 2. Lexical Syntax & 18 Feature Vector Deconstruction
- Expand **Inspect Model Input Vector** to view all 18 structural, statistical, and lexical features extracted in real time.
- View protocol security, host resolution, and TLD reputation badges.

### 3. Adversarial Red-Team Simulator ("What-If" Studio)
- Scroll down to the **Adversarial Red-Team Simulator**.
- Select a clean starting domain (e.g., `google.com`, `shooliniuniversity.com`, `paypal.com`).
- Toggle any of the 6 attack vectors:
  - **Strip HTTPS / Downgrade HTTP**: Removes TLS encryption.
  - **Brand Typosquatting / Homoglyph**: Inserts brand deception tokens.
  - **Raw IP Address Host**: Bypasses DNS resolution.
  - **Hex / Percent Character Obfuscation**: Encodes characters with `%20`, `%2E`, etc.
  - **Deep Subdomain Spoofing**: Adds deceptive prefixes (`secure.login.verify...`).
  - **Query Entropy & Token Padding**: Adds deceptive tracking parameters.
- Observe how the synthesized URL changes dynamically, which defense tier catches it, and how the phishing probability updates instantly.

### 4. Bulk Feed Ingestion Console
- Click the **Bulk Threat Feed Scanner** tab.
- Paste multiple URLs (one per line) or upload a `.txt` list.
- Click **Execute Batch Scan** to inspect hundreds of URLs simultaneously.
- Click **Export Forensics (CSV)** to download an incident report.

### 5. Algorithm Comparison Modal
- Click **Model & Benchmarks** in the header.
- View the comparative table, test set accuracy spectrum, F1-score spectrum, and mathematical bias-variance proof.

---

## 🔌 Programmatic REST API Usage

PhishGuard AI exposes a production JSON REST endpoint at `/api/predict`.

### Using `curl`:
```bash
curl -X POST http://127.0.0.1:5000/api/predict \
     -H "Content-Type: application/json" \
     -d '{"url": "https://paypal-security-account.com/login"}'
```

### JSON Response:
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

### Using Python:
```python
import requests

url = "http://127.0.0.1:5000/api/predict"
payload = {"url": "https://shooliniuniversity.com"}
response = requests.post(url, json=payload)
data = response.json()

print(f"URL: {data['url']}")
print(f"Verdict: {data['prediction']} ({data['risk_score']}% Risk)")
print(f"Defense Tier: {data['defense_tier']}")
```

---

## 🛠️ Troubleshooting & FAQs

### Q1: `ModuleNotFoundError: No module named 'flask'` (or other package)
**Fix:** Ensure your virtual environment is activated (`ml_env`). Check that `pip install -r requirements.txt` completed without errors.

### Q2: Port 5000 is already in use
**Fix:** Another process is listening on port 5000. You can run app on a different port by editing the last line of `app.py`:
```python
app.run(debug=False, port=5001)
```
Or kill the process using port 5000 in PowerShell:
```powershell
Get-Process -Id (Get-NetTCPConnection -LocalPort 5000).OwningProcess | Stop-Process
```

### Q3: `FileNotFoundError: models/phishing_url_model.pkl`
**Fix:** The `.pkl` model files can be generated in 4 seconds by executing:
```bash
python train_comparative_models.py
```
This builds and saves all 4 model binaries into the `models/` directory.

### Q4: PowerShell execution policy error when activating `ml_env`
**Fix:** Run this one-time command in PowerShell:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
Then run `.\ml_env\Scripts\Activate.ps1` again.

---

## 📂 Repository Directory Map

```text
Phishing-Website-Detector/
│
├── app.py                         # Flask application & HTTP REST routing
├── config.py                      # Centralized environment configuration (.env loader)
├── predictor.py                   # 4-Tier Hybrid Defense-in-Depth Pipeline
├── url_features.py                # 18-Signal Structural & Lexical Feature Extractor
├── train_comparative_models.py    # Multi-model training, benchmarking & audit generator
├── retrain.py                     # Champion Random Forest training script
├── requirements.txt               # Pinned Python dependencies
├── .env.example                   # Environment variable template
├── .gitignore                     # Git exclusion rules
├── EXECUTION_GUIDE.md             # This comprehensive execution & setup manual
├── README.md                      # GitHub presentation & technical overview
├── LICENSE                        # MIT Open Source License
│
├── scripts/
│   └── debug_url.py               # Standalone CLI URL forensic debugger
│
├── tests/
│   └── test_pipeline.py           # Automated unit & integration test suite
│
├── static/
│   └── style.css                  # Obsidian glassmorphic UI stylesheet
│
├── templates/
│   └── index.html                 # Complete Jinja2 command center interface
│
└── models/                        # Serialized ML binaries & benchmark audit files
    ├── phishing_url_model.pkl     # Deployed Random Forest Champion (100 Trees)
    ├── decision_tree_model.pkl    # CART Decision Tree
    ├── linear_svm_model.pkl       # Support Vector Classifier
    ├── logistic_regression_model.pkl # Generalized Linear Classifier
    ├── training_benchmark_proof.txt # Human-readable viva proof report
    └── model_comparison_benchmark.json # Machine-readable benchmark metrics
```
