"""
tests/test_pipeline.py
----------------------
Comprehensive integration and unit test suite for PhishGuard AI.
Verifies feature extraction, multi-tier threat classification, and REST API routes.
"""

import unittest
from url_features import extract_url_features, LIVE_FEATURES
from predictor import predict_url, is_valid_url_format, detect_brand_impersonation
from app import app


class TestURLFeatures(unittest.TestCase):
    """Test URL feature extraction consistency."""

    def test_live_features_count(self):
        self.assertEqual(len(LIVE_FEATURES), 18)

    def test_extracted_feature_keys(self):
        feat = extract_url_features("https://www.google.com/search?q=test")
        for k in LIVE_FEATURES:
            self.assertIn(k, feat)
            self.assertIsInstance(feat[k], (int, float))

    def test_empty_url_raises(self):
        with self.assertRaises(ValueError):
            extract_url_features("")


class TestFormatValidation(unittest.TestCase):
    """Test URL structural syntax checking."""

    def test_plain_text_rejected(self):
        self.assertFalse(is_valid_url_format("hello world"))
        self.assertFalse(is_valid_url_format("jfjf"))
        self.assertFalse(is_valid_url_format("how are you"))
        self.assertFalse(is_valid_url_format("plain text without dot"))

    def test_valid_urls_accepted(self):
        self.assertTrue(is_valid_url_format("https://google.com"))
        self.assertTrue(is_valid_url_format("wikipedia.org/wiki/AI"))
        self.assertTrue(is_valid_url_format("http://192.168.1.1/admin"))
        self.assertTrue(is_valid_url_format("https://login.shooliniuniversity.com/feed"))


class TestMultiTierEngine(unittest.TestCase):
    """Test multi-tier decision routing."""

    def test_tier1_authority_allowlist(self):
        res = predict_url("https://www.google.com")
        self.assertEqual(res["result"], "LEGITIMATE")
        self.assertEqual(res["defense_tier"], "Tier 1: Authority Allowlist")
        self.assertLessEqual(res["phishing_probability"], 1.0)

    def test_tier2_brand_impersonation(self):
        brand = detect_brand_impersonation("https://paypal-security-account-verify.com/login")
        self.assertEqual(brand, "Paypal")
        res = predict_url("https://paypal-security-account-verify.com/login")
        self.assertEqual(res["result"], "PHISHING")
        self.assertEqual(res["defense_tier"], "Tier 2: Brand Impersonation Engine")
        self.assertGreaterEqual(res["phishing_probability"], 99.0)

    def test_tier3_ml_prediction(self):
        res = predict_url("http://service-mitld.firebaseapp.com/")
        self.assertIn(res["result"], ["PHISHING", "LEGITIMATE"])
        self.assertIn("defense_tier", res)


class TestFlaskAPIRoutes(unittest.TestCase):
    """Test Flask web and JSON REST endpoints."""

    def setUp(self):
        app.testing = True
        self.client = app.test_client()

    def test_home_page(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)

    def test_healthcheck(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertTrue(data["model_loaded"])

    def test_api_predict_valid(self):
        resp = self.client.post("/api/predict", json={"url": "https://www.google.com"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["result"], "LEGITIMATE")

    def test_api_predict_invalid_plain_text(self):
        resp = self.client.post("/api/predict", json={"url": "just plain conversational text"})
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertEqual(data["result"], "INVALID")
        self.assertEqual(data["inspection_notes"], "Plain Text")

    def test_api_batch_predict(self):
        batch = {
            "urls": [
                "https://www.google.com",
                "hello invalid",
                "https://paypal-security-center.com/login"
            ]
        }
        resp = self.client.post("/api/batch_predict", json=batch)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["count"], 3)
        self.assertEqual(data["results"][0]["result"], "LEGITIMATE")
        self.assertEqual(data["results"][1]["result"], "INVALID")
        self.assertEqual(data["results"][1]["inspection_notes"], "Plain Text")
        self.assertIsNone(data["results"][1]["phishing_probability"])
        self.assertEqual(data["results"][2]["result"], "PHISHING")


if __name__ == "__main__":
    unittest.main()
