from flask import Flask, request, render_template, jsonify
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
            insights=result.get("insights", []),
            impersonation_warning=result.get("impersonation_warning"),
        )

    except Exception:
        return render_template(
            "index.html",
            url=url,
            error="Unable to analyze this URL. Please enter a valid URL."
        )


@app.route("/api/predict", methods=["POST"])
def api_predict():
    """
    JSON API endpoint for programmatic URL analysis.
    Accepts:
        POST /api/predict
        Content-Type: application/json
        Body: { "url": "https://example.com" }
    """
    data = request.get_json(silent=True) or request.form
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({
            "status": "error",
            "message": "URL parameter is required."
        }), 400

    try:
        result = predict_url(url)
        return jsonify({
            "status": "success",
            "url": url,
            "result": result["result"],
            "phishing_probability": result["phishing_probability"],
            "legitimate_probability": result["legitimate_probability"],
            "impersonation_warning": result.get("impersonation_warning"),
            "insights": result.get("insights", []),
        }), 200

    except Exception:
        return jsonify({
            "status": "error",
            "message": "Unable to analyze this URL. Please verify the URL format."
        }), 422


@app.route("/api/batch_predict", methods=["POST"])
def api_batch_predict():
    """
    JSON API endpoint for bulk URL analysis.
    Accepts:
        POST /api/batch_predict
        Body: { "urls": ["https://site1.com", "https://site2.com"] }
    """
    data = request.get_json(silent=True) or {}
    urls = data.get("urls", [])

    if isinstance(urls, str):
        urls = [u.strip() for u in urls.splitlines() if u.strip()]

    if not urls:
        return jsonify({
            "status": "error",
            "message": "At least one URL is required."
        }), 400

    results = []
    # Process up to 25 URLs per batch
    for u in urls[:25]:
        u_clean = u.strip()
        if not u_clean:
            continue
        try:
            pred = predict_url(u_clean)
            results.append({
                "url": u_clean,
                "result": pred["result"],
                "phishing_probability": pred["phishing_probability"],
                "legitimate_probability": pred["legitimate_probability"],
                "impersonation_warning": pred.get("impersonation_warning"),
                "status": "success",
            })
        except Exception:
            results.append({
                "url": u_clean,
                "result": "INVALID",
                "phishing_probability": 0,
                "legitimate_probability": 0,
                "impersonation_warning": None,
                "status": "failed",
            })

    return jsonify({
        "status": "success",
        "count": len(results),
        "results": results,
    }), 200


if __name__ == "__main__":
    app.run(debug=True)