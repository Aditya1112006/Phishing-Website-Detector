"""
scripts/data_preprocessing.py
-----------------------------
PhishGuard AI — Advanced Dataset Preprocessing & Debiasing Engine.

Addresses the 4 core empirical biases discovered in PhiUSIIL Phishing Dataset:
1. Protocol Shortcut Bias: 100% of legitimate URLs were HTTPS (IsHTTPS=0 was 0).
   -> Counterfactual Data Augmentation (CDA) synthesizes balanced HTTP legitimate
      and HTTPS phishing records to decouple protocol from label.
2. Query/Path Absence in Legitimate Data: Legitimate URLs lacked query parameters.
   -> Augments benign search/REST query parameters into legitimate samples.
3. Feature Calculation Divergence: Raw dataset features (NoOfLetters, LetterRatio)
   diverged from standard extraction. We re-extract all 18 features directly from
   raw URL strings using `url_features.extract_url_features()` to ensure 100%
   mathematical parity between training and inference.
4. Feature Skewness & Outliers: Extreme positive skewness (>100) on symbol counts.
   -> Applies 99.5th percentile robust quantile Winsorization.
"""

import os
import sys
import time

# Ensure project root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pandas as pd
from urllib.parse import urlparse
from url_features import extract_url_features, LIVE_FEATURES

RAW_DATA_PATH = os.path.join("data", "Phishing_Dataset.csv")
OUTPUT_DATA_PATH = os.path.join("data", "debiased_features_corpus.csv")
OUTPUT_PARQUET_PATH = os.path.join("data", "debiased_features_corpus.parquet")

FEATURES_18 = LIVE_FEATURES


def extract_base_domain(url: str) -> str:
    """Extract normalized base netloc for group-aware partitioning."""
    try:
        s = str(url).strip()
        if not s.startswith(("http://", "https://", "ftp://")):
            s = "https://" + s
        netloc = urlparse(s).netloc.lower().split(":")[0].rstrip(".")
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc if netloc else "unknown-domain"
    except Exception:
        return "unknown-domain"


def generate_debiased_corpus():
    print("=" * 76)
    print("  PHISHGUARD AI — DATASET DEBIASING & FEATURE ALIGNMENT PIPELINE")
    print("=" * 76)

    t0 = time.time()
    if not os.path.exists(RAW_DATA_PATH):
        raise FileNotFoundError(f"Raw dataset not found at {RAW_DATA_PATH}")

    print(f"\n[1/6] Loading raw dataset from {RAW_DATA_PATH} ...")
    df = pd.read_csv(RAW_DATA_PATH, usecols=["URL", "label"])
    print(f"      Loaded {len(df):,} records in {time.time()-t0:.2f}s.")

    # Deduplicate on URL
    initial_count = len(df)
    df = df.drop_duplicates(subset="URL", keep="first").reset_index(drop=True)
    print(f"      Deduplication: {initial_count:,} -> {len(df):,} records ({initial_count - len(df):,} dropped).")

    # Feature extraction with 100% training-serving mathematical parity
    print("\n[2/6] Extracting live 18 features directly from URL strings for training-serving parity ...")
    t_feat = time.time()
    url_list = df["URL"].tolist()
    extracted_records = [extract_url_features(u) for u in url_list]
    feat_df = pd.DataFrame(extracted_records)
    for col in FEATURES_18:
        df[col] = feat_df[col]
    df["BaseDomain"] = df["URL"].apply(extract_base_domain)
    print(f"      Extracted 18 features for {len(df):,} URLs in {time.time()-t_feat:.2f}s.")

    # Inspect pre-debiasing protocol stats
    print("\n[3/6] Pre-debiasing Protocol Distribution (The Shortcut Bias):")
    ct_pre = pd.crosstab(df["IsHTTPS"], df["label"])
    print(ct_pre)
    legit_http_pre = ct_pre.loc[0, 1] if 0 in ct_pre.index and 1 in ct_pre.columns else 0
    print(f"      Notice: Legitimate HTTP count was only {legit_http_pre:,}!")

    # -----------------------------------------------------------------------
    # Counterfactual Data Augmentation (CDA)
    # -----------------------------------------------------------------------
    print("\n[4/6] Applying Counterfactual Data Augmentation (CDA) ...")
    np.random.seed(42)

    # A. Synthesize Legitimate HTTP URLs (decoupling IsHTTPS=0 from Phishing)
    legit_https = df[(df["label"] == 1) & (df["IsHTTPS"] == 1)]
    sample_size_legit = min(35000, len(legit_https))
    cda_legit_sample = legit_https.sample(n=sample_size_legit, random_state=42)
    cda_legit_urls = cda_legit_sample["URL"].astype(str).str.replace("^https://", "http://", regex=True).tolist()
    cda_legit_feats = [extract_url_features(u) for u in cda_legit_urls]
    cda_legit_http = pd.DataFrame(cda_legit_feats)
    cda_legit_http["URL"] = cda_legit_urls
    cda_legit_http["label"] = 1
    cda_legit_http["BaseDomain"] = cda_legit_sample["BaseDomain"].values
    print(f"      + Synthesized {len(cda_legit_http):,} Legitimate HTTP URLs (IsHTTPS=0, label=1)")

    # B. Synthesize Phishing HTTPS URLs (modern TLS-encrypted phishing)
    phish_http = df[(df["label"] == 0) & (df["IsHTTPS"] == 0)]
    sample_size_phish = min(35000, len(phish_http))
    cda_phish_sample = phish_http.sample(n=sample_size_phish, random_state=42)
    cda_phish_urls = cda_phish_sample["URL"].astype(str).str.replace("^http://", "https://", regex=True).tolist()
    cda_phish_feats = [extract_url_features(u) for u in cda_phish_urls]
    cda_phish_https = pd.DataFrame(cda_phish_feats)
    cda_phish_https["URL"] = cda_phish_urls
    cda_phish_https["label"] = 0
    cda_phish_https["BaseDomain"] = cda_phish_sample["BaseDomain"].values
    print(f"      + Synthesized {len(cda_phish_https):,} Modern Phishing HTTPS URLs (IsHTTPS=1, label=0)")

    # C. Synthesize Legitimate Query & Path Samples (breaking '?' and '=' absence in benign)
    sample_size_query = min(25000, len(legit_https))
    cda_query_sample = legit_https.sample(n=sample_size_query, random_state=1337)
    query_templates = [
        "/search?q=product&lang=en",
        "/view?id=1024&category=news",
        "/articles/index.html?page=2&ref=home",
        "/item?productId=48201&sort=asc",
        "/catalog/search.php?query=test&filter=all"
    ]
    chosen_templates = np.random.choice(query_templates, size=sample_size_query)
    cda_query_urls = [u.rstrip("/") + t for u, t in zip(cda_query_sample["URL"].astype(str), chosen_templates)]
    cda_query_feats = [extract_url_features(u) for u in cda_query_urls]
    cda_legit_queries = pd.DataFrame(cda_query_feats)
    cda_legit_queries["URL"] = cda_query_urls
    cda_legit_queries["label"] = 1
    cda_legit_queries["BaseDomain"] = cda_query_sample["BaseDomain"].values
    print(f"      + Synthesized {len(cda_legit_queries):,} Legitimate Query/Path URLs (queries on label=1)")

    # Combine original and counterfactual augmented datasets
    debiased_df = pd.concat([df, cda_legit_http, cda_phish_https, cda_legit_queries], ignore_index=True)
    debiased_df = debiased_df.drop_duplicates(subset=["URL"], keep="first").reset_index(drop=True)
    print(f"      Total corpus after Counterfactual Augmentation: {len(debiased_df):,} records.")

    # -----------------------------------------------------------------------
    # Robust Quantile Winsorization (Outlier Capping on Skewed Features)
    # -----------------------------------------------------------------------
    print("\n[5/6] Applying 99.5th Percentile Robust Quantile Winsorization ...")
    skewed_features = [
        'URLLength', 'DomainLength', 'NoOfDegitsInURL', 'NoOfEqualsInURL',
        'NoOfAmpersandInURL', 'NoOfObfuscatedChar', 'NoOfHyphensInURL'
    ]
    for feat in skewed_features:
        cap_val = float(debiased_df[feat].quantile(0.995))
        before_max = debiased_df[feat].max()
        debiased_df[feat] = np.minimum(debiased_df[feat], cap_val)
        print(f"      - {feat:20}: Max {before_max} capped at Q99.5 = {cap_val:.1f}")

    # Inspect post-debiasing protocol stats
    print("\n[6/6] Post-debiasing Protocol Cross-Tabulation (Shortcut Eliminated):")
    ct_post = pd.crosstab(debiased_df["IsHTTPS"], debiased_df["label"])
    print(ct_post)

    # -----------------------------------------------------------------------
    # Save Processed Dataset
    # -----------------------------------------------------------------------
    print(f"\n--> Saving debiased dataset to {OUTPUT_DATA_PATH} ...")
    cols_to_save = ["URL", "BaseDomain", "label"] + FEATURES_18
    debiased_df[cols_to_save].to_csv(OUTPUT_DATA_PATH, index=False)
    print(f"    Saved CSV: {OUTPUT_DATA_PATH} ({os.path.getsize(OUTPUT_DATA_PATH):,} bytes)")

    print("\n" + "=" * 76)
    print("  PREPROCESSING & DEBIASING COMPLETE!")
    print(f"  Total records: {len(debiased_df):,} | Time elapsed: {time.time()-t0:.2f}s")
    print("=" * 76)
    return debiased_df


if __name__ == "__main__":
    generate_debiased_corpus()
