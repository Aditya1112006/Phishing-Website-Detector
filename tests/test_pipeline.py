"""
tests/test_pipeline.py
----------------------
Comprehensive test suite for PhishGuard AI covering:
  1. Feature extraction consistency & case-sensitivity
  2. Structural URL format validation (IPv4, IPv6, ports, non-web schemes)
  3. Multi-tier decision routing (Tiers 1 - 4)
  4. Performance & latency benchmarks
  5. Flask web application & REST API routes
"""

import time
import unittest
from url_features import extract_url_features, LIVE_FEATURES
from predictor import (
    predict_url,
    is_valid_url_format,
    detect_brand_impersonation,
    deconstruct_url_syntax,
    is_trusted_domain,
)
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

    def test_case_insensitive_http_protocol(self):
        feat_http = extract_url_features("HTTP://EXAMPLE.COM")
        self.assertEqual(feat_http["IsHTTPS"], 0)
        self.assertEqual(feat_http["DomainLength"], len("example.com"))

        feat_https = extract_url_features("HTTPS://EXAMPLE.COM")
        self.assertEqual(feat_https["IsHTTPS"], 1)
        self.assertEqual(feat_https["DomainLength"], len("example.com"))

    def test_obfuscation_detection(self):
        feat = extract_url_features("https://example.com/%20%2E%2E%2Flogin")
        self.assertEqual(feat["HasObfuscation"], 1)
        self.assertGreaterEqual(feat["NoOfObfuscatedChar"], 3)

    def test_empty_url_raises(self):
        with self.assertRaises(ValueError):
            extract_url_features("")


class TestFormatValidation(unittest.TestCase):
    """Test URL structural syntax checking on normal, invalid, and edge cases."""

    def test_plain_text_rejected(self):
        self.assertFalse(is_valid_url_format("hello world"))
        self.assertFalse(is_valid_url_format("jfjf"))
        self.assertFalse(is_valid_url_format("how are you today?"))
        self.assertFalse(is_valid_url_format("plain text without dot"))
        self.assertFalse(is_valid_url_format("   "))
        self.assertFalse(is_valid_url_format(""))

    def test_non_web_schemes_rejected(self):
        self.assertFalse(is_valid_url_format("mailto:admin@example.com"))
        self.assertFalse(is_valid_url_format("javascript:alert(1)"))
        self.assertFalse(is_valid_url_format("data:text/html;base64,PHNjcmlwdD5h"))
        self.assertFalse(is_valid_url_format("file:///etc/passwd"))
        self.assertFalse(is_valid_url_format("tel:+1234567890"))

    def test_spaces_within_url_rejected(self):
        self.assertFalse(is_valid_url_format("https://google.com /search"))
        self.assertFalse(is_valid_url_format("https:// has space.com"))

    def test_normal_web_urls_accepted(self):
        self.assertTrue(is_valid_url_format("https://google.com"))
        self.assertTrue(is_valid_url_format("wikipedia.org/wiki/AI"))
        self.assertTrue(is_valid_url_format("https://login.shooliniuniversity.com/feed"))
        self.assertTrue(is_valid_url_format("http://service-mitld.firebaseapp.com/"))

    def test_case_insensitive_schemes(self):
        self.assertTrue(is_valid_url_format("HTTPS://WWW.GOOGLE.COM/SEARCH?Q=TEST"))
        self.assertTrue(is_valid_url_format("Http://Example.Com/Path"))

    def test_ipv4_and_ipv6_hosts(self):
        self.assertTrue(is_valid_url_format("http://192.168.1.1/admin"))
        self.assertTrue(is_valid_url_format("http://8.8.8.8:8080"))
        self.assertTrue(is_valid_url_format("http://[::1]:8080/path"))
        self.assertTrue(is_valid_url_format("http://[2001:db8::1]/"))

    def test_ports_and_trailing_dots(self):
        self.assertTrue(is_valid_url_format("https://example.com:8443/login"))
        self.assertTrue(is_valid_url_format("https://www.google.com./"))


class TestMultiTierEngine(unittest.TestCase):
    """Test multi-tier decision routing across normal and adversarial cases."""

    def test_tier1_authority_allowlist(self):
        res = predict_url("https://www.google.com")
        self.assertEqual(res["result"], "LEGITIMATE")
        self.assertEqual(res["defense_tier"], "Tier 1: Authority Allowlist")
        self.assertLessEqual(res["phishing_probability"], 1.0)

    def test_tier1_insecure_http_handling(self):
        # Plain HTTP on an authority domain is recognized as legitimate with unencrypted protocol advisory
        res = predict_url("http://www.google.com")
        self.assertEqual(res["result"], "LEGITIMATE")
        self.assertEqual(res["defense_tier"], "Tier 1: Authority Allowlist")
        self.assertIn("HTTP", res["inspection_notes"])

    def test_tier2_brand_impersonation(self):
        res_paypal = predict_url("https://paypal-security-account-verify.com/login")
        self.assertEqual(res_paypal["result"], "PHISHING")
        self.assertEqual(res_paypal["defense_tier"], "Tier 2: Brand Impersonation Engine")
        self.assertGreaterEqual(res_paypal["phishing_probability"], 99.0)

        res_netflix = predict_url("https://netflix-billing-update.org/verify")
        self.assertEqual(res_netflix["result"], "PHISHING")
        self.assertEqual(res_netflix["defense_tier"], "Tier 2: Brand Impersonation Engine")

    def test_tier3_ml_prediction(self):
        res = predict_url("http://service-mitld.firebaseapp.com/")
        self.assertIn(res["result"], ["PHISHING", "LEGITIMATE"])
        self.assertIn("defense_tier", res)

    def test_syntax_deconstructor_ipv6(self):
        tokens = deconstruct_url_syntax("http://[2001:db8::1]:8080/dashboard")
        self.assertTrue(tokens["is_ip"])
        self.assertEqual(tokens["port"], 8080)


class TestPerformance(unittest.TestCase):
    """Ensure sub-millisecond feature extraction and rapid inference."""

    def test_feature_extraction_latency(self):
        t0 = time.perf_counter()
        for _ in range(100):
            extract_url_features("https://www.google.com/search?q=machine+learning&lang=en")
        elapsed_per_call_ms = ((time.perf_counter() - t0) / 100) * 1000
        self.assertLess(elapsed_per_call_ms, 1.0, f"Extraction too slow: {elapsed_per_call_ms:.3f}ms")

    def test_full_prediction_latency(self):
        t0 = time.perf_counter()
        predict_url("https://www.google.com")
        elapsed_ms = (time.perf_counter() - t0) * 1000
        self.assertLess(elapsed_ms, 25.0, f"Single prediction too slow: {elapsed_ms:.3f}ms")


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
                "hello invalid text",
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

    def test_404_api_not_found(self):
        resp = self.client.get("/api/non_existent_route")
        self.assertEqual(resp.status_code, 404)
        data = resp.get_json()
        self.assertEqual(data["status"], "error")

    def test_rfc_2606_reserved_documentation_domains(self):
        """Test RFC 2606 reserved domains (example.com) are classified as Legitimate."""
        for i in range(1, 26):
            url = f"https://example.com/test-{i}"
            res = predict_url(url)
            self.assertEqual(res["result"], "LEGITIMATE")
            self.assertIn("RFC 2606", res.get("inspection_notes", ""))
            self.assertEqual(res["defense_tier"], "Tier 1: Authority Allowlist")

    def test_batch_predict_truncation_feedback(self):
        """Test that submitting 26 URLs provides clear truncation metadata and warning."""
        urls = [f"https://example.com/test-{i}" for i in range(1, 27)]
        resp = self.client.post("/api/batch_predict", json={"urls": urls})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["total_submitted"], 26)
        self.assertEqual(data["total_processed"], 25)
        self.assertEqual(data["omitted_count"], 1)
        self.assertIsNotNone(data["warning"])
        self.assertIn("omitted", data["warning"])

    def test_benchmark_metrics_mathematical_consistency(self):
        """Test that benchmark JSON metrics match the confusion matrix exactly."""
        import json
        with open("models/model_comparison_benchmark.json", "r", encoding="utf-8") as f:
            benchmarks = json.load(f)
        champ = next(b for b in benchmarks if b.get("is_champion"))
        cm = champ["confusion_matrix"]
        tp, tn, fp, fn = cm["true_positive"], cm["true_negative"], cm["false_positive"], cm["false_negative"]
        total = tp + tn + fp + fn
        acc = round((tp + tn) / total * 100, 2)
        prec = round(tp / (tp + fp) * 100, 2)
        rec = round(tp / (tp + fn) * 100, 2)
        f1 = round(2 * ((prec / 100) * (rec / 100)) / ((prec / 100) + (rec / 100)) * 100, 2)

        self.assertAlmostEqual(champ["accuracy_pct"], acc, places=2)
        self.assertAlmostEqual(champ["precision_pct"], prec, places=2)
        self.assertAlmostEqual(champ["recall_pct"], rec, places=2)
        self.assertAlmostEqual(champ["f1_score_pct"], f1, places=2)

    def test_counterfactual_legitimate_http_resilience(self):
        """Test that legitimate sites accessed over HTTP are not falsely flagged as phishing."""
        for u in [
            "http://www.google.com",
            "http://en.wikipedia.org",
            "http://example.com",
            "http://shooliniuniversity.com"
        ]:
            res = predict_url(u)
            self.assertEqual(res["result"], "LEGITIMATE", f"Failed on {u}: got {res['result']}")

    def test_counterfactual_https_phishing_detection(self):
        """Test that modern phishing URLs using TLS (HTTPS) are correctly flagged."""
        for u in [
            "https://netflix-billing-update.org",
            "https://paypal-security-center.com/login",
            "https://appleid-verify-alert.com/account"
        ]:
            res = predict_url(u)
            self.assertEqual(res["result"], "PHISHING", f"Failed on {u}: got {res['result']}")

    def test_counterfactual_benign_query_strings(self):
        """Test that legitimate deep URLs with queries do not trigger false positives."""
        for u in [
            "https://en.wikipedia.org/wiki/Machine_learning?action=edit&lang=en",
            "https://www.google.com/search?q=cybersecurity+threat+intelligence&hl=en",
            "https://github.com/search?q=machine-learning&type=repositories"
        ]:
            res = predict_url(u)
            self.assertEqual(res["result"], "LEGITIMATE", f"Failed on {u}: got {res['result']}")

    def test_localhost_and_rfc_single_label_hosts(self):
        """Test that single-label RFC reserved hosts like localhost are valid formats."""
        for u in ["http://localhost:5000", "http://localhost/", "https://example.com"]:
            self.assertTrue(is_valid_url_format(u), f"Should be valid URL format: {u}")
            res = predict_url(u)
            self.assertEqual(res["result"], "LEGITIMATE")

    def test_own_app_instance_and_standard_domain_insight(self):
        """Test that own app URL is legitimate and standard domains do not show threat badges."""
        res_app = predict_url("https://phishguard-ai-xwol.onrender.com/")
        self.assertEqual(res_app["result"], "LEGITIMATE")
        self.assertEqual(res_app["defense_tier"], "Tier 1: Authority Allowlist")

        # Test unlisted standard domain has safe=True on Domain Authority insight
        res_std = predict_url("https://a-random-safe-company-blog.com/")
        auth_insight = next(i for i in res_std["insights"] if i["name"] == "Domain Authority")
        self.assertTrue(auth_insight["safe"], "Standard domain should be safe/neutral, not red risk")
        self.assertEqual(auth_insight["badge"], "Standard")


if __name__ == "__main__":
    unittest.main()
