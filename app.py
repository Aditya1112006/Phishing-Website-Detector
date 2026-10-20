from flask import Flask
import joblib

app = Flask(__name__)

# Load trained model and feature list
model = joblib.load("models/phishing_url_model.pkl")
features = joblib.load("models/phishing_url_features.pkl")


@app.route("/")
def home():
    return "Phishing URL Detector is running!"


if __name__ == "__main__":
    app.run(debug=True)