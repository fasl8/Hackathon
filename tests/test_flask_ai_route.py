import csv
import io
import unittest
from unittest.mock import patch

try:
    import app as app_module
except ModuleNotFoundError as exc:
    if exc.name == "flask":
        raise unittest.SkipTest("Install project requirements to run Flask route tests")
    raise


class FlaskAIRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()

    def test_health_reports_ai_configuration(self):
        with patch.object(app_module, "GEMINI_API_KEY", ""):
            response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["ai_content_analysis_configured"])

    def test_ai_route_explains_missing_key(self):
        with patch.object(app_module, "GEMINI_API_KEY", ""):
            response = self.client.post(
                "/api/ai/analyze",
                json={"text": "رسالة تجريبية تطلب إدخال رمز OTP خلال عشر دقائق"},
            )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["status"], "not_configured")
        self.assertIn("يُرجى إعداد GEMINI_API_KEY", response.get_json()["message_ar"])

    def test_ai_route_rejects_short_text(self):
        with patch.object(app_module, "GEMINI_API_KEY", "test-key"):
            response = self.client.post("/api/ai/analyze", json={"text": "Hi"})
        self.assertEqual(response.status_code, 400)

    def test_batch_scan_endpoint_is_removed(self):
        response = self.client.post("/api/scan/batch", json={"urls": ["https://example.com"]})
        self.assertEqual(response.status_code, 404)

    def test_csv_export_uses_arabic_column_headers(self):
        response = self.client.post(
            "/api/export/csv",
            json={"results": [{"case_id": "TEST", "source": "search", "risk_level": "high", "verdict": "suspicious"}]},
        )
        rows = list(csv.reader(io.StringIO(response.get_data(as_text=True).lstrip("\ufeff"))))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(rows[0][0], "رقم الحالة")
        self.assertEqual(rows[0][1], "وقت التحليل (UTC)")
        self.assertEqual(rows[1][2:3], ["نتيجة بحث"])
        self.assertEqual(rows[1][6:8], ["مرتفع", "اشتباه"])


if __name__ == "__main__":
    unittest.main()
