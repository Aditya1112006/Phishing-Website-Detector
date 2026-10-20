# Phishing URL Detector

A machine learning web application that analyzes URLs and classifies them as **phishing** or **legitimate** using a trained Random Forest classifier.

Built with Python, scikit-learn, and Flask.

---

## Overview

This project builds an end-to-end phishing URL detection system:

1. A **URL feature extractor** parses structural properties of any given URL.
2. A **Random Forest model** trained on those features classifies the URL.
3. A **Flask web application** provides a browser-based interface for real-time predictions.

> **Important:** This is a URL-only classifier. It analyzes the structure and composition of the URL itself — it does **not** fetch or scan the webpage content, HTML, JavaScript, forms, or external resources.

---

## Model

### Dataset
- **Source:** [PhiUSIIL Phishing URL Dataset](https://www.kaggle.com/datasets/ndarvind/phiusiil-phishing-url-dataset?resource=download) (Kaggle)
- **Size:** 235,795 URLs (235,370 after duplicate URL removal)
- **Labels:** `0` = Phishing, `1` = Legitimate

### Feature Engineering
Rather than attempting to reproduce the dataset's original 55 features (many of which require webpage fetching and are not reproducible for arbitrary live URLs), a custom URL feature extractor was built and applied consistently to both training data and live predictions.

**13 URL-based features used by the deployed model:**

| Feature | Description |
|---|---|
| `URLLength` | Total length of the URL string |
| `DomainLength` | Length of the domain (excluding `www.`) |
| `IsDomainIP` | Whether the domain is a raw IP address |
| `TLDLength` | Length of the top-level domain |
| `NoOfSubDomain` | Number of subdomains |
| `HasObfuscation` | Whether percent-encoded characters are present |
| `NoOfObfuscatedChar` | Count of percent-encoded characters |
| `ObfuscationRatio` | Ratio of percent-encoded characters to URL length |
| `NoOfLettersInURL` | Count of alphabetic characters in the URL |
| `NoOfDegitsInURL` | Count of digits in the URL |
| `NoOfEqualsInURL` | Count of `=` characters |
| `NoOfQMarkInURL` | Count of `?` characters |
| `NoOfAmpersandInURL` | Count of `&` characters |

> **Note:** `IsHTTPS` was intentionally excluded from the deployed model. The training dataset showed that 100% of legitimate samples used HTTPS, making this feature a dataset-specific shortcut rather than a generalizable signal.

### Model Performance (held-out test set)

| Metric | Score |
|---|---|
| Accuracy | 99.5369% |
| Precision | 99.3871% |
| Recall | 99.8072% |
| F1 Score | 99.5970% |

These results are from an 80/20 stratified split of the PhiUSIIL-derived dataset after duplicate URL removal. They do **not** represent guaranteed real-world performance on unseen domains.

### Model Algorithm
- **Random Forest** (`n_estimators=100`, `random_state=42`)
- No feature scaling required (tree-based model)

---

## Project Structure

```
Machine Learning/
│
├── app.py                  # Flask application (routes + prediction logic)
│
├── models/
│   ├── phishing_url_model.pkl      # Deployed 13-feature Random Forest model
│   ├── phishing_url_features.pkl   # Feature name list for the deployed model
│   ├── phishing_random_forest.pkl  # Original 49-feature research model (not deployed)
│   └── final_features.pkl          # Feature list for the research model
│
├── templates/
│   └── index.html          # Frontend UI template (Jinja2)
│
├── static/
│   └── style.css           # Stylesheet
│
├── data/
│   └── Phishing_Dataset.csv
│
├── notebooks/
│   └── 01_dataset_exploration.ipynb
│
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

---

## Setup & Running Locally

### 1. Clone the repository
```bash
git clone https://github.com/Aditya1112006/Phishing-Website-Detector.git
cd Phishing-Website-Detector
```

### 2. Create and activate a virtual environment
```bash
python -m venv ml_env

# Windows
ml_env\Scripts\activate

# macOS / Linux
source ml_env/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Flask application
```bash
python app.py
```

### 5. Open in browser
```
http://127.0.0.1:5000
```

---

## Usage

1. Enter any URL in the input field (e.g., `https://example.com`).
2. Click **Check URL**.
3. The application will display:
   - **Prediction:** PHISHING or LEGITIMATE
   - **Phishing probability**
   - **Legitimate probability**
   - Visual probability bars

---

## Known Limitations

- **URL-only analysis:** The model uses only structural URL features. It does not fetch or inspect the webpage, JavaScript, HTML forms, certificates, or DNS records.
- **No external threat intelligence:** There is no integration with threat feeds, VirusTotal, Google Safe Browsing, or WHOIS data.
- **Dataset scope:** Performance metrics are based on the PhiUSIIL dataset. Real-world accuracy on completely unseen domains may differ.
- **Model probabilities are estimates:** A high phishing probability does not prove malicious intent; a high legitimate probability does not guarantee safety.
- **HTTPS is not a safety indicator:** HTTPS was deliberately excluded from the model due to dataset bias. This classifier does not treat HTTPS as evidence of legitimacy.

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3 |
| ML Model | scikit-learn (Random Forest) |
| Web Framework | Flask |
| Data Processing | pandas, numpy |
| Model Persistence | joblib |
| Frontend | HTML, CSS, Jinja2 |

---

## License

This project is licensed under the terms of the [LICENSE](LICENSE) file.
