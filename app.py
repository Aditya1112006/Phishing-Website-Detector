from flask import Flask, request, render_template
from predictor import predict_url

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    url = request.form.get("url", "").strip()

    # Guard: empty input
    if not url:
        return render_template(
            "index.html",
            error="Please enter a URL."
        )

    try:
        result = predict_url(url)

        return render_template(
            "index.html",
            url=url,
            result=result["result"],
            phishing_probability=result["phishing_probability"],
            legitimate_probability=result["legitimate_probability"],
        )

    except Exception:
        return render_template(
            "index.html",
            url=url,
            error="Unable to analyze this URL. Please enter a valid URL."
        )


if __name__ == "__main__":
    app.run(debug=True)