import unittest
from security_engine import analyze_url


class ScamShieldRuleEngineTests(unittest.TestCase):
    def test_user_facing_validation_and_indicator_text_is_arabic(self):
        with self.assertRaisesRegex(ValueError, "يُرجى إدخال رابط"):
            analyze_url("", enable_rdap=False)

        result = analyze_url("http://192.168.1.10/login", enable_rdap=False)
        labels = {item["label"] for item in result["indicators"]}
        self.assertIn("استخدام عنوان IP كاسم للمضيف", labels)

    def test_verified_uaepass_domain_not_flagged_as_lookalike(self):
        result = analyze_url("https://selfcare.uaepass.ae", enable_rdap=False)
        self.assertFalse(result["brand_impersonation"]["detected"])
        self.assertEqual(result["verified_official_domain"], "uaepass.ae")

    def test_verified_tamm_domain_not_flagged_as_lookalike(self):
        result = analyze_url("https://tamm.abudhabi", enable_rdap=False)
        self.assertFalse(result["brand_impersonation"]["detected"])
        self.assertEqual(result["verified_official_domain"], "tamm.abudhabi")

    def test_paypal_lookalike(self):
        result = analyze_url("https://paypa1.com", enable_rdap=False)
        self.assertTrue(result["brand_impersonation"]["detected"])
        self.assertEqual(result["brand_impersonation"]["brand"], "PayPal")
        self.assertGreaterEqual(result["risk_score"], 60)

    def test_microsoft_lookalike_subdomain(self):
        result = analyze_url("https://login.micros0oft.com", enable_rdap=False)
        self.assertTrue(result["brand_impersonation"]["detected"])
        self.assertEqual(result["brand_impersonation"]["brand"], "Microsoft")

    def test_shortener_is_not_automatically_called_malicious(self):
        result = analyze_url("https://bit.ly/example", enable_rdap=False)
        self.assertTrue(result["shortened_url"])
        self.assertNotEqual(result["verdict"], "confirmed_or_multiple_high_risk_signals")
        self.assertTrue(any(x["code"] == "shortener" for x in result["indicators"]))

    def test_redirect_to_lookalike_is_detected(self):
        result = analyze_url("https://example.com/redirect?url=https%3A%2F%2Fpaypa1.com", enable_rdap=False)
        codes = {x["code"] for x in result["indicators"]}
        self.assertIn("external_redirect_parameter", codes)
        self.assertIn("redirect_brand_impersonation", codes)

    def test_ip_literal_is_flagged(self):
        result = analyze_url("http://192.168.1.10/login", enable_rdap=False)
        codes = {x["code"] for x in result["indicators"]}
        self.assertIn("ip_host", codes)
        self.assertIn("non_global_ip", codes)

    def test_bad_scheme_rejected(self):
        with self.assertRaises(ValueError):
            analyze_url("javascript:alert(1)", enable_rdap=False)

    def test_official_adcb_domain_not_flagged(self):
        result = analyze_url("https://www.adcb.com", enable_rdap=False)
        self.assertEqual(result["verified_official_domain"], "adcb.com")
        self.assertFalse(result["brand_impersonation"]["detected"])

    def test_official_subdomain_is_trusted_match_not_auto_safe(self):
        result = analyze_url("https://login.adpolice.gov.ae", enable_rdap=False)
        self.assertEqual(result["verified_official_domain"], "adpolice.gov.ae")
        self.assertEqual(result["verdict"], "verified_official_domain_match")


if __name__ == "__main__":
    unittest.main(verbosity=2)
