import joblib
f = joblib.load("models/phishing_url_features.pkl")
print(f"Feature count: {len(f)}")
print(f"Has IsHTTPS: {'IsHTTPS' in f}")
print(f"Has NoOfSlashesInURL: {'NoOfSlashesInURL' in f}")
print(f"Features: {f}")
