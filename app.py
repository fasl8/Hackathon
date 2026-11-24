"""Flask API for ScamShield AI - hybrid rules and Gemini content analysis."""
from __future__ import annotations

import csv
import io
import os
from flask import Flask, jsonify, make_response, render_template, request

from security_engine import analyze_url, load_local_blocklist, set_local_blocklist
from ai_analyzer import analyze_scam_content, AIAnalyzerError, AIConfigurationError, DEFAULT_MODEL

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
app.logger.setLevel("INFO")

set_local_blocklist(load_local_blocklist(os.path.join(BASE_DIR, "data", "known_bad_urls.txt")))
GOOGLE_WEB_RISK_API_KEY = os.getenv("GOOGLE_WEB_RISK_API_KEY", "").strip()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL
ENABLE_RDAP = os.getenv("ENABLE_RDAP", "0").strip().lower() in {"1", "true", "yes", "on"}
ALLOWED_SOURCES = {"message", "search", "maps", "social", "other"}


def _source(value):
    value = str(value or "other").strip().lower()
    return value if value in ALLOWED_SOURCES else "other"


def _csv_safe(value):
    text = str(value if value is not None else "")
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "engine": "ScamShield Rule-Based Threat Engine",
        "url_ml_model_required": False,
        "google_web_risk_configured": bool(GOOGLE_WEB_RISK_API_KEY),
        "ai_content_analysis_configured": bool(GEMINI_API_KEY),
        "ai_provider": "Google Gemini API",
        "ai_model": GEMINI_MODEL,
        "rdap_enabled": ENABLE_RDAP,
        "supported_sources": sorted(ALLOWED_SOURCES),
    })


@app.post("/api/scan")
def scan():
    body = request.get_json(silent=True) or {}
    raw_url = body.get("url", "")
    source = _source(body.get("source", "message"))
    try:
        result = analyze_url(
            raw_url,
            source=source,
            web_risk_api_key=GOOGLE_WEB_RISK_API_KEY or None,
            enable_rdap=ENABLE_RDAP,
        )
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        app.logger.exception("URL analysis failed")
        return jsonify({"error": "حدث خطأ أثناء تحليل الرابط. يُرجى مراجعة سجل التطبيق."}), 500


@app.post("/api/ai/analyze")
def ai_analyze():
    body = request.get_json(silent=True) or {}
    try:
        result = analyze_scam_content(
            text=body.get("text", ""),
            context_url=body.get("context_url", ""),
            source=body.get("source", "message"),
            api_key=GEMINI_API_KEY or None,
            model=GEMINI_MODEL,
        )
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except AIConfigurationError as exc:
        app.logger.warning("AI content analysis is not configured: %s", exc)
        return jsonify({
            "status": "not_configured",
            "error": "تحليل الذكاء الاصطناعي غير مُهيأ",
            "message_ar": "لإتاحة تحليل الذكاء الاصطناعي، يُرجى إعداد GEMINI_API_KEY في الطرفية ثم إعادة تشغيل التطبيق.",
        }), 503
    except AIAnalyzerError as exc:
        app.logger.exception("Gemini content analysis failed")
        return jsonify({
            "status": "provider_error",
            "error": "تحليل الذكاء الاصطناعي غير متاح مؤقتاً",
            "message_ar": "تعذر الاتصال بخدمة الذكاء الاصطناعي. يُرجى التحقق من المفتاح والاتصال والحصة المتاحة.",
        }), 502
    except Exception:
        app.logger.exception("Unexpected AI content analysis failure")
        return jsonify({"error": "حدث خطأ غير متوقع في تحليل المحتوى بالذكاء الاصطناعي."}), 500


@app.post("/api/export/csv")
def export_csv():
    body = request.get_json(silent=True) or {}
    rows = body.get("results")
    if not isinstance(rows, list) or not rows or len(rows) > 200:
        return jsonify({"error": "يُرجى إرسال من 1 إلى 200 نتيجة للتصدير"}), 400
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["رقم الحالة", "وقت التحليل (UTC)", "المصدر", "الرابط المُدخل", "النطاق المسجل", "درجة الخطورة", "مستوى الخطورة", "النتيجة", "العلامة التجارية", "أسباب المؤشرات", "بصمة الدليل SHA-256"])
    source_labels = {
        "message": "رسالة أو رابط مباشر",
        "search": "نتيجة بحث",
        "maps": "خرائط",
        "social": "تواصل اجتماعي",
        "other": "أخرى",
    }
    risk_labels = {"critical": "حرج", "high": "مرتفع", "medium": "متوسط", "low": "منخفض", "unknown": "غير محسوم"}
    verdict_labels = {
        "confirmed_or_multiple_high_risk_signals": "مؤشرات خطورة مؤكدة أو متعددة",
        "suspicious": "اشتباه",
        "needs_review": "يحتاج إلى مراجعة",
        "no_strong_signals": "لم تظهر مؤشرات قوية",
        "verified_official_domain_match": "مطابقة نطاق رسمي موثق",
    }
    for row in rows:
        if not isinstance(row, dict):
            continue
        brand = (row.get("brand_impersonation") or {}).get("brand") or ""
        reasons = " | ".join(item.get("detail", "") for item in row.get("indicators", []) if isinstance(item, dict))
        source = str(row.get("source") or "")
        risk_level = str(row.get("risk_level") or "")
        verdict = str(row.get("verdict") or "")
        writer.writerow([_csv_safe(value) for value in [
            row.get("case_id", ""), row.get("analysis_timestamp_utc", ""), source_labels.get(source, source),
            row.get("submitted_url", ""), row.get("registered_domain", ""), row.get("risk_score", ""),
            risk_labels.get(risk_level, risk_level), verdict_labels.get(verdict, verdict), brand, reasons,
            row.get("evidence_sha256", ""),
        ]])
    response = make_response("\ufeff" + output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=scamshield_evidence.csv"
    return response


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
