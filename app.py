from flask import Flask, request, render_template, jsonify
from predictor import predict_url, is_valid_url_format

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    url = request.form.get("url", "").strip()

    # Guard 1: empty input
    if not url:
        return render_template(
            "index.html",
            error="Please enter a destination URL."
        )

    # Guard 2: validate URL format (reject plain conversational text, sentences, spaces)
    if not is_valid_url_format(url):
        return render_template(
            "index.html",
            url=url,
            error=f"Invalid URL Format: '{url}' is plain text, not a valid web URL or domain name. Real URLs cannot contain spaces and must be valid web destinations (e.g., https://example.com/login or google.com)."
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
            defense_tier=result.get("defense_tier"),
            defense_tier_description=result.get("defense_tier_description"),
            raw_features=result.get("raw_features", {}),
            risk_severity=result.get("risk_severity"),
            severity_tag_class=result.get("severity_tag_class"),
            actionable_advisory=result.get("actionable_advisory"),
            syntax_tokens=result.get("syntax_tokens"),
        )

    except ValueError as ve:
        return render_template(
            "index.html",
            url=url,
            error=str(ve)
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

    if not is_valid_url_format(url):
        return jsonify({
            "status": "error",
            "result": "INVALID",
            "message": f"Invalid URL format: '{url}' is plain text, not a valid web URL or domain name.",
            "defense_tier": "Format Validation",
            "inspection_notes": "Plain Text"
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
            "defense_tier": result.get("defense_tier"),
            "defense_tier_description": result.get("defense_tier_description"),
            "insights": result.get("insights", []),
            "raw_features": result.get("raw_features", {}),
            "risk_severity": result.get("risk_severity"),
            "severity_tag_class": result.get("severity_tag_class"),
            "actionable_advisory": result.get("actionable_advisory"),
            "syntax_tokens": result.get("syntax_tokens"),
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

        if not is_valid_url_format(u_clean):
            results.append({
                "url": u_clean,
                "result": "INVALID",
                "phishing_probability": None,
                "legitimate_probability": None,
                "impersonation_warning": None,
                "defense_tier": "Format Validation",
                "inspection_notes": "Plain Text",
                "status": "invalid",
            })
            continue

        try:
            pred = predict_url(u_clean)
            results.append({
                "url": u_clean,
                "result": pred["result"],
                "phishing_probability": pred["phishing_probability"],
                "legitimate_probability": pred["legitimate_probability"],
                "impersonation_warning": pred.get("impersonation_warning"),
                "defense_tier": pred.get("defense_tier"),
                "inspection_notes": "⚠️ Brand Spoofing" if pred.get("impersonation_warning") else ("Structural Anomaly" if pred["result"] == "PHISHING" else "Verified Clean"),
                "status": "success",
            })
        except Exception:
            results.append({
                "url": u_clean,
                "result": "INVALID",
                "phishing_probability": None,
                "legitimate_probability": None,
                "impersonation_warning": None,
                "defense_tier": "Format Validation",
                "inspection_notes": "Plain Text",
                "status": "invalid",
            })

    return jsonify({
        "status": "success",
        "count": len(results),
        "results": results,
    }), 200


if __name__ == "__main__":
    app.run(debug=True)