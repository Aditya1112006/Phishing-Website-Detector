"""
retrain.py
----------
Retrains the Phishing URL Detector model using the updated URL feature
extractor defined in url_features.py.

Run this script once whenever url_features.py is updated:

    python retrain.py

Output
------
Overwrites (or creates):
    models/phishing_url_model.pkl
    models/phishing_url_features.pkl

After this completes, restart app.py to load the new model.
"""

import time
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)
from url_features import extract_url_features, LIVE_FEATURES


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DATA_PATH      = "data/Phishing_Dataset.csv"
SUPPLEMENT_PATH = "data/supplement_legit.txt"
MODEL_PATH     = "models/phishing_url_model.pkl"
FEATURES_PATH  = "models/phishing_url_features.pkl"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    sep = "=" * 62
    print(sep)
    print("  Phishing URL Detector — Model Retraining")
    print(f"  Features: {len(LIVE_FEATURES)}")
    print(sep)

    # ------------------------------------------------------------------
    # 1. Load dataset
    # ------------------------------------------------------------------
    print(f"\n[1/6]  Loading dataset ...")
    df_raw = pd.read_csv(DATA_PATH)
    print(f"       Loaded {len(df_raw):,} rows, {df_raw.shape[1]} columns.")

    # ------------------------------------------------------------------
    # 2. Remove duplicate URLs (same as original pipeline)
    # ------------------------------------------------------------------
    print(f"\n[2/7]  Removing duplicate URLs ...")
    df_raw = df_raw.drop_duplicates(subset="URL", keep="first").reset_index(drop=True)
    print(f"       After deduplication: {len(df_raw):,} unique URLs.")

    # ------------------------------------------------------------------
    # 3. Load supplementary famous legitimate sites
    # ------------------------------------------------------------------
    print(f"\n[3/7]  Loading supplementary legitimate sites from {SUPPLEMENT_PATH} ...")
    supp_urls = []
    try:
        with open(SUPPLEMENT_PATH, "r", encoding="utf-8") as fh:
            for line in fh:
                domain = line.strip()
                if not domain or domain.startswith("#"):
                    continue
                # Generate multiple realistic URL patterns per domain.
                # Covers trailing slashes, www/bare, and common paths so the
                # model learns the full spectrum of legitimate URL structure.
                variants = [
                    f"https://www.{domain}",              # standard homepage
                    f"https://{domain}",                  # bare domain
                    f"https://www.{domain}/",             # trailing slash
                    f"https://{domain}/",                 # bare + trailing slash
                    f"https://www.{domain}/about",        # common path
                    f"https://www.{domain}/contact",
                    f"https://www.{domain}/blog",
                    f"https://{domain}/about",
                    f"https://{domain}/home",
                    f"https://www.{domain}/get-started",  # hyphen in path
                    f"https://{domain}/learn-more",       # hyphen in path, no www
                    f"https://{domain}/some-project/overview",  # multi-segment path
                    f"https://www.{domain}/docs/guide",   # deeper path
                ]
                supp_urls.extend(variants)
        # Remove exact duplicates while preserving order
        supp_urls = list(dict.fromkeys(supp_urls))
        n_domains = len(supp_urls) // 13
        print(f"       Loaded {len(supp_urls):,} supplementary URLs (~{n_domains} domains x 13 variants).")
    except FileNotFoundError:
        print(f"       WARNING: {SUPPLEMENT_PATH} not found. Skipping supplementary data.")
        supp_urls = []

    # ------------------------------------------------------------------
    # 4. Extract URL features
    # ------------------------------------------------------------------
    print(f"\n[4/7]  Extracting features for {len(df_raw):,} PhiUSIIL URLs ...")
    print("       This may take 1-2 minutes ...")
    t0 = time.time()

    def safe_extract(url):
        try:
            return extract_url_features(url)
        except Exception:
            return None

    raw_records = df_raw["URL"].apply(safe_extract)
    failed = raw_records.isna().sum()
    if failed:
        print(f"       WARNING: {failed} URLs failed extraction and will be dropped.")

    df_feat = pd.DataFrame(raw_records.tolist())
    df_feat["label"] = df_raw["label"].values
    df_feat = df_feat.dropna(subset=LIVE_FEATURES).reset_index(drop=True)

    elapsed = time.time() - t0
    print(f"       Done in {elapsed:.1f}s.  PhiUSIIL rows: {len(df_feat):,}")

    # ------------------------------------------------------------------
    # 5. Extract features for supplementary sites and combine
    # ------------------------------------------------------------------
    if supp_urls:
        print(f"\n[5/7]  Extracting features for {len(supp_urls):,} supplementary URLs ...")
        supp_records = [safe_extract(u) for u in supp_urls]
        df_supp = pd.DataFrame([r for r in supp_records if r is not None])
        df_supp["label"] = 1  # All supplementary = legitimate
        df_supp = df_supp.dropna(subset=LIVE_FEATURES).reset_index(drop=True)
        print(f"       Supplementary rows added: {len(df_supp):,}")

        df_feat = pd.concat([df_feat, df_supp], ignore_index=True)
        print(f"       Combined dataset size: {len(df_feat):,}")
    else:
        print(f"\n[5/7]  No supplementary data -- skipping.")

    # ------------------------------------------------------------------
    # 6. Prepare X / y
    # ------------------------------------------------------------------
    print(f"\n[6/7]  Preparing features and labels ...")
    X = df_feat[LIVE_FEATURES]
    y = df_feat["label"]

    dist = dict(y.value_counts().sort_index())
    print(f"       Label distribution — 0 (Phishing): {dist.get(0, 0):,}  "
          f"| 1 (Legitimate): {dist.get(1, 0):,}")

    # 80 / 20 stratified split
    # Supplementary sites go into TRAINING ONLY (not test)
    # to preserve a clean PhiUSIIL-only test evaluation.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"       Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # ------------------------------------------------------------------
    # 7. Train
    # ------------------------------------------------------------------
    print(f"\n[7/7]  Training Random Forest (n_estimators=100, n_jobs=-1) ...")
    t0 = time.time()
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    elapsed = time.time() - t0
    print(f"       Training complete in {elapsed:.1f}s.")

    # ------------------------------------------------------------------
    # Evaluate
    # ------------------------------------------------------------------
    print(f"\n       Evaluating on held-out test set ...")
    y_pred = clf.predict(X_test)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec  = recall_score(y_test, y_pred)
    f1   = f1_score(y_test, y_pred)
    cm   = confusion_matrix(y_test, y_pred)

    print()
    print(f"       Accuracy  : {acc  * 100:.4f}%")
    print(f"       Precision : {prec * 100:.4f}%")
    print(f"       Recall    : {rec  * 100:.4f}%")
    print(f"       F1 Score  : {f1   * 100:.4f}%")
    print(f"\n       Confusion matrix (rows=actual, cols=predicted):")
    print(f"       {cm}")

    # Feature importances
    importances = (
        pd.Series(clf.feature_importances_, index=LIVE_FEATURES)
        .sort_values(ascending=False)
    )
    print(f"\n       Feature importances:")
    for feat, imp in importances.items():
        bar = "#" * int(imp * 60)
        print(f"       {feat:<25} {imp:.6f}  {bar}")

    # ------------------------------------------------------------------
    # Save model files
    # ------------------------------------------------------------------
    print(f"\n       Saving {MODEL_PATH} ...")
    joblib.dump(clf, MODEL_PATH)

    print(f"       Saving {FEATURES_PATH} ...")
    joblib.dump(LIVE_FEATURES, FEATURES_PATH)

    print(f"\n{sep}")
    print("  Retraining complete.")
    print("  Restart app.py to load the new model.")
    print(sep)


if __name__ == "__main__":
    main()
