import os
import unittest
from unittest.mock import patch

from ai_analyzer import (
    AIConfigurationError,
    analyze_scam_content,
    _validate_output,
)


class AIAnalyzerUnitTests(unittest.TestCase):
    def test_requires_text(self):
        with self.assertRaisesRegex(ValueError, "يُرجى إدخال نص الرسالة"):
            analyze_scam_content("")

    def test_enforces_text_length(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": "demo-key"}):
            with self.assertRaises(ValueError):
                analyze_scam_content("A" * 7001)

    def test_missing_key_is_explicit(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(AIConfigurationError):
                analyze_scam_content("رسالة تجريبية تطلب رمز التحقق")

    def test_unverified_quotes_are_removed(self):
        content = "يرجى إدخال رمز OTP خلال 24 ساعة"
        payload = {
            "language": "Arabic",
            "assessment": "likely_scam",
            "scam_type": "credential_theft",
            "risk_level": "high",
            "impersonated_brand": "UAE PASS",
            "red_flags": ["طلب رمز تحقق"],
            "evidence_quotes": ["رمز OTP خلال 24 ساعة", "موقع حكومي رسمي موثّق"],
            "sensitive_requests": ["OTP"],
            "summary_ar": "طلب حساس.",
            "summary_en": "Sensitive request.",
            "recommended_action_ar": "لا تشاركي الرمز.",
        }
        result = _validate_output(payload, content)
        self.assertEqual(result["evidence_quotes"], ["رمز OTP خلال 24 ساعة"])

    def test_unknown_enum_values_are_safely_normalised(self):
        result = _validate_output({"risk_level": "100%", "assessment": "definitely_bad"}, "هذه رسالة")
        self.assertEqual(result["risk_level"], "uncertain")
        self.assertEqual(result["assessment"], "uncertain")


if __name__ == "__main__":
    unittest.main()
