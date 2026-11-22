"""
app.py
------
Flask application and REST API server for PhishGuard AI.
Provides single-target forensic scanning, bulk feed ingestion, and JSON REST endpoints.
"""

import logging
from flask import Flask, request, render_template, jsonify
from config import Config
from predictor import predict_url, is_valid_url_format, get_model_and_features

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("phishguard")

app = Flask(__name__)
app.config["SECRET_KEY"] = Config.SECRET_KEY


# ---------------------------------------------------------------------------
# HTTP Error Handlers
# ---------------------------------------------------------------------------
@app.errorhandler(400)
def handle_bad_request(e):
    if request.path.startswith("/api/"):
        return jsonify({"status": "error", "error": "Bad Request", "message": str(e)}), 400
    return render_template("index.html", error="Bad request. Please verify your input."), 400


@app.errorhandler(404)
def handle_not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"status": "error", "error": "Not Found", "message": "Endpoint not found."}), 404
    return render_template("index.html", error="The requested page does not exist."), 404


@app.errorhandler(500)
def handle_internal_server_error(e):
    logger.error("Internal Server Error: %s", e)
    if request.path.startswith("/api/"):
        return jsonify({"status": "error", "error": "Internal Server Error", "message": "An unexpected error occurred."}), 500
    return render_template("index.html", error="An internal server error occurred. Please try again."), 500


# ---------------------------------------------------------------------------
# Web Routes
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    """Render the main PhishGuard AI Cyber Threat Intelligence dashboard."""
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    """Handle interactive single-URL forensic scan submissions."""
    url = request.form.get("url", "").strip()

    if not url:
        return render_template("index.html", error="Please enter a destination URL to inspect.")

    if not is_valid_url_format(url):
        return render_template(
            "index.html",
            url=url,
            error=f"Invalid URL Format: '{url}' is plain text or an invalid format. URLs cannot contain whitespace and must resolve to a valid domain or IP."
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
        return render_template("index.html", url=url, error=str(ve))
    except Exception as exc:
        logger.error("Scan failure for '%s': %s", url, exc)
        return render_template("index.html", url=url, error="Analysis pipeline encountered an error. Please verify the URL.")


# ---------------------------------------------------------------------------
# Programmatic JSON REST Endpoints
# ---------------------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def api_health():
    """Healthcheck endpoint reporting model artifact readiness."""
    try:
        _, _ = get_model_and_features()
        model_ready = True
    except Exception:
        model_ready = False

    return jsonify({
        "status": "healthy" if model_ready else "degraded",
        "service": "PhishGuard AI Threat Intelligence",
        "model_loaded": model_ready,
        "defense_architecture": "4-Tier Hybrid Pipeline"
    }), 200 if model_ready else 503


@app.route("/api/predict", methods=["POST"])
def api_predict():
    """
    JSON API endpoint for programmatic URL analysis.
    Payload: { "url": "https://example.com" }
    """
    data = request.get_json(silent=True) or request.form
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"status": "error", "message": "The 'url' parameter is required."}), 400

    if not is_valid_url_format(url):
        return jsonify({
            "status": "error",
            "result": "INVALID",
            "message": f"Invalid URL format: '{url}' is plain text or an invalid domain.",
            "defense_tier": "Format Validation",
            "inspection_notes": "Plain Text"
        }), 400

    try:
        res = predict_url(url)
        return jsonify({
            "status": "success",
            "url": url,
            "result": res["result"],
            "phishing_probability": res["phishing_probability"],
            "legitimate_probability": res["legitimate_probability"],
            "impersonation_warning": res.get("impersonation_warning"),
            "defense_tier": res.get("defense_tier"),
            "defense_tier_description": res.get("defense_tier_description"),
            "insights": res.get("insights", []),
            "raw_features": res.get("raw_features", {}),
            "risk_severity": res.get("risk_severity"),
            "severity_tag_class": res.get("severity_tag_class"),
            "actionable_advisory": res.get("actionable_advisory"),
            "syntax_tokens": res.get("syntax_tokens"),
        }), 200
    except Exception as exc:
        logger.error("API predict failed for '%s': %s", url, exc)
        return jsonify({"status": "error", "message": "Failed to analyze URL."}), 422


@app.route("/api/batch_predict", methods=["POST"])
def api_batch_predict():
    """
    JSON API endpoint for bulk threat feed scanning.
    Payload: { "urls": ["https://site1.com", "https://site2.com"] }
    """
    data = request.get_json(silent=True) or {}
    urls = data.get("urls", [])

    if isinstance(urls, str):
        urls = [u.strip() for u in urls.splitlines() if u.strip()]

    if not urls:
        return jsonify({"status": "error", "message": "At least one URL is required in the 'urls' list."}), 400

    results = []
    # Cap batch processing to configured maximum
    for u in urls[:Config.MAX_BATCH_URLS]:
        clean_u = u.strip()
        if not clean_u:
            continue

        if not is_valid_url_format(clean_u):
            results.append({
                "url": clean_u,
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
            pred = predict_url(clean_u)
            results.append({
                "url": clean_u,
                "result": pred["result"],
                "phishing_probability": pred["phishing_probability"],
                "legitimate_probability": pred["legitimate_probability"],
                "impersonation_warning": pred.get("impersonation_warning"),
                "defense_tier": pred.get("defense_tier"),
                "inspection_notes": (
                    "⚠️ Brand Spoofing" if pred.get("impersonation_warning")
                    else ("Structural Anomaly" if pred["result"] == "PHISHING" else "Verified Clean")
                ),
                "status": "success",
            })
        except Exception as exc:
            logger.warning("Batch item '%s' failed: %s", clean_u, exc)
            results.append({
                "url": clean_u,
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
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
