"""ScamShield lightweight URL threat analysis engine (no ML model required)."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import time
import uuid
from datetime import datetime, timezone
from difflib import SequenceMatcher
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, unquote, urlparse, urlunparse
from urllib.request import Request, urlopen

# Official domains verified against the organisations' own sites or UAE government references.
# Add or change entries only after checking an official source.
UAE_BRANDS = {
    "UAE PASS": {
        "tokens": ["uaepass", "uae-pass"],
        "official_domains": ["uaepass.ae"],
    },
    "TAMM": {
        "tokens": ["tamm"],
        "official_domains": ["tamm.abudhabi"],
    },
    "Abu Dhabi Police": {
        "tokens": ["adpolice", "abudhabipolice"],
        "official_domains": ["adpolice.gov.ae"],
    },
    "Emirates NBD": {
        "tokens": ["emiratesnbd"],
        "official_domains": ["emiratesnbd.com"],
    },
    "ADCB": {
        "tokens": ["adcb"],
        "official_domains": ["adcb.com"],
    },
    "FAB": {
        "tokens": ["bankfab", "fab"],
        "official_domains": ["bankfab.com"],
    },
    "Dubai Islamic Bank": {
        "tokens": ["dib"],
        "official_domains": ["dib.ae"],
    },
}

GLOBAL_BRANDS = {
    "PayPal": {"tokens": ["paypal"], "official_domains": ["paypal.com"]},
    "Microsoft": {"tokens": ["microsoft"], "official_domains": ["microsoft.com"]},
    "Google": {"tokens": ["google"], "official_domains": ["google.com"]},
    "Amazon": {"tokens": ["amazon"], "official_domains": ["amazon.com"]},
    "Apple": {"tokens": ["apple"], "official_domains": ["apple.com"]},
    "Netflix": {"tokens": ["netflix"], "official_domains": ["netflix.com"]},
}
BRANDS = {**UAE_BRANDS, **GLOBAL_BRANDS}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "shorturl.at", "is.gd", "ow.ly",
    "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy", "lnkd.in", "s.id",
}
SUSPICIOUS_TLDS = {".top", ".xyz", ".click", ".work", ".buzz", ".tk", ".rest", ".fit"}
SUSPICIOUS_HOST_WORDS = {
    "login", "verify", "secure", "account", "wallet", "support", "payment",
    "update", "password", "signin", "confirm", "refund", "fine", "fines",
}
ARABIC_SCAM_TERMS = {"مخالفات", "الغرامات", "سداد", "دفع", "تحقق", "تحديث", "حساب", "بطاقة", "بنك", "استرداد", "مكافأة"}
RISKY_EXTENSIONS = {".exe", ".apk", ".scr", ".bat", ".msi", ".dmg", ".zip"}
REDIRECT_KEYS = {"url", "target", "redirect", "redirect_url", "next", "continue", "dest", "destination", "return", "returnurl"}
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au", "co.nz",
    "com.sg", "com.my", "co.in", "firm.in", "net.in", "org.in", "co.jp",
    "com.br", "com.tr", "com.sa", "com.eg", "com.ae", "gov.ae", "ac.ae",
}

# Keep this list tiny and curated. A positive match is high-confidence evidence.
LOCAL_BAD_URLS = set()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _normalise_url(raw_url: str) -> tuple[str, str, str]:
    if not isinstance(raw_url, str):
        raise ValueError("يجب أن يكون الرابط نصاً")
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("يُرجى إدخال رابط")
    if len(raw_url) > 4096:
        raise ValueError("الرابط أطول من الحد المسموح (4096 حرفاً)")
    # Treat a bare domain as HTTPS. Never silently accept javascript:, file:, data:, etc.
    candidate = raw_url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url) else "https://" + raw_url
    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("يمكن تحليل روابط HTTP وHTTPS فقط")
    if not parsed.hostname:
        raise ValueError("لا يحتوي الرابط على اسم مضيف صالح")
    if parsed.username is not None or parsed.password is not None:
        # Do not discard this evidence: keep URL normalized but flag later.
        pass
    try:
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("تعذر فك ترميز اسم النطاق") from exc
    if not host or any(ch.isspace() for ch in host):
        raise ValueError("اسم المضيف غير صالح")
    try:
        _ = parsed.port  # raises on malformed ports
    except ValueError as exc:
        raise ValueError("يحتوي الرابط على رقم منفذ غير صالح") from exc
    userinfo = ""
    if parsed.username is not None:
        userinfo = parsed.username
        if parsed.password is not None:
            userinfo += ":" + parsed.password
        userinfo += "@"
    netloc = userinfo + host
    if parsed.port:
        netloc += ":" + str(parsed.port)
    normalized = urlunparse((parsed.scheme.lower(), netloc, parsed.path or "/", "", parsed.query, ""))
    return normalized, host, parsed.scheme.lower()


def _registrable_domain(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    suffix2 = ".".join(labels[-2:])
    if suffix2 in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix2


def _root_label(domain: str) -> str:
    try:
        ipaddress.ip_address(domain)
        return domain
    except ValueError:
        return domain.split(".")[0]


def _normalise_brand_token(value: str) -> str:
    value = value.lower().replace("-", "").replace("_", "")
    value = value.translate(str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "8": "b", "@": "a"}))
    return value


def _official_brand_for_host(host: str):
    for brand_name, info in BRANDS.items():
        for official in info["official_domains"]:
            if host == official or host.endswith("." + official):
                return brand_name, official
    return None, None


def detect_brand_impersonation(host: str) -> dict:
    official_brand, official_domain = _official_brand_for_host(host)
    if official_brand:
        return {
            "detected": False,
            "brand": official_brand,
            "similarity": 1.0,
            "official_domain_match": official_domain,
            "reason": "نطاق رسمي أو نطاق فرعي مطابق تماماً",
        }

    domain = _registrable_domain(host)
    root = _root_label(domain)
    labels = host.split(".")
    # Include a subdomain label only if it explicitly contains a brand token, e.g. google-login.example.com.
    candidates = [root]
    candidates.extend(label for label in labels[:-len(domain.split("."))] if label and label != "www")
    candidates.extend(label for label in labels[:-1] if label not in candidates and label != "www")

    best = {"detected": False, "brand": None, "similarity": 0.0, "official_domain_match": None, "reason": None}
    for candidate in candidates:
        cleaned = _normalise_brand_token(candidate)
        for brand_name, info in BRANDS.items():
            for token in info["tokens"]:
                expected = _normalise_brand_token(token)
                # A separate brand token is suspicious (e.g. uaepass-secure.com).
                candidate_parts = re.split(r"[-_]", candidate.lower())
                separated = any(_normalise_brand_token(part) == expected for part in candidate_parts)
                score = SequenceMatcher(None, cleaned, expected).ratio()
                if cleaned == expected or separated or (len(expected) >= 5 and abs(len(cleaned) - len(expected)) <= 2 and score >= 0.84):
                    confidence = 1.0 if (cleaned == expected or separated) else score
                    if confidence > best["similarity"] or not best["detected"]:
                        best = {
                            "detected": True,
                            "brand": brand_name,
                            "similarity": round(float(confidence), 4),
                            "official_domain_match": None,
                            "reason": "يحتوي النطاق على اسم علامة محمية أو يشبهها",
                        }
    return best


def _extract_redirect_targets(parsed) -> list[str]:
    targets = []
    try:
        query = parse_qs(parsed.query, keep_blank_values=False)
    except ValueError:
        return targets
    for key, values in query.items():
        if key.lower() in REDIRECT_KEYS:
            for value in values[:2]:
                decoded = unquote(value).strip()
                if decoded.startswith(("http://", "https://")):
                    targets.append(decoded[:2048])
    return targets[:3]


def _check_web_risk(url: str, api_key: str | None) -> dict:
    if not api_key:
        return {"provider": "Google Web Risk", "status": "not_configured", "matches": []}
    from urllib.parse import urlencode
    params = urlencode([
        ("threatTypes", "SOCIAL_ENGINEERING"),
        ("threatTypes", "MALWARE"),
        ("threatTypes", "UNWANTED_SOFTWARE"),
        ("uri", url),
        ("key", api_key),
    ])
    endpoint = "https://webrisk.googleapis.com/v1/uris:search?" + params
    try:
        req = Request(endpoint, headers={"User-Agent": "ScamShield-AI/1.0"})
        with urlopen(req, timeout=3.5) as response:
            payload = json.loads(response.read(512_000).decode("utf-8"))
        matches = payload.get("threat", {}).get("threatTypes", [])
        return {"provider": "Google Web Risk", "status": "match" if matches else "no_match", "matches": matches}
    except HTTPError as exc:
        return {"provider": "Google Web Risk", "status": "provider_error", "matches": [], "detail": "HTTP " + str(exc.code)}
    except (URLError, TimeoutError, ValueError, OSError):
        return {"provider": "Google Web Risk", "status": "unavailable", "matches": []}


def _check_rdap_domain_age(domain: str, enabled: bool) -> dict:
    if not enabled:
        return {"status": "not_enabled", "age_days": None, "registration_date": None}
    try:
        # RDAP.org is a bootstrap service that directs the lookup to the appropriate registry.
        endpoint = "https://rdap.org/domain/" + quote(domain, safe=".-")
        req = Request(endpoint, headers={"Accept": "application/rdap+json", "User-Agent": "ScamShield-AI/1.0"})
        with urlopen(req, timeout=3.0) as response:
            payload = json.loads(response.read(512_000).decode("utf-8"))
        dates = []
        for event in payload.get("events", []):
            if event.get("eventAction", "").lower() in {"registration", "registered"}:
                raw = event.get("eventDate")
                if raw:
                    dates.append(datetime.fromisoformat(raw.replace("Z", "+00:00")))
        if not dates:
            return {"status": "no_registration_date", "age_days": None, "registration_date": None}
        registered = min(dates)
        age = max(0, (datetime.now(timezone.utc) - registered.astimezone(timezone.utc)).days)
        return {"status": "available", "age_days": age, "registration_date": registered.date().isoformat()}
    except HTTPError as exc:
        return {"status": "not_found" if exc.code == 404 else "provider_error", "age_days": None, "registration_date": None}
    except (URLError, TimeoutError, ValueError, OSError, KeyError, TypeError):
        return {"status": "unavailable", "age_days": None, "registration_date": None}


def _indicator(code: str, label: str, weight: int, detail: str, source: str = "local_rule") -> dict:
    return {"code": code, "label": label, "weight": weight, "detail": detail, "source": source}


def analyze_url(raw_url: str, source: str = "message", web_risk_api_key: str | None = None,
                enable_rdap: bool = False) -> dict:
    normalized, host, scheme = _normalise_url(raw_url)
    parsed = urlparse(normalized)
    registered_domain = _registrable_domain(host)
    indicators = []
    intel = []
    score = 0

    official_brand, official_domain = _official_brand_for_host(host)
    brand_result = detect_brand_impersonation(host)

    if normalized.lower() in LOCAL_BAD_URLS:
        indicators.append(_indicator("local_blocklist_match", "رابط معروف بأنه ضار", 100,
                                      "تطابق تام مع رابط في قائمة الحظر المحلية المُعدة", "local_blocklist"))
        score = 100

    web_risk = _check_web_risk(normalized, web_risk_api_key)
    intel.append(web_risk)
    if web_risk["status"] == "match":
        threat_labels = {
            "SOCIAL_ENGINEERING": "هندسة اجتماعية",
            "MALWARE": "برمجيات ضارة",
            "UNWANTED_SOFTWARE": "برمجيات غير مرغوب فيها",
        }
        threat_names = [threat_labels.get(item, item) for item in web_risk["matches"]]
        indicators.append(_indicator("web_risk_match", "مدرج في خدمة Google Web Risk", 100,
                                      "أنواع التهديد: " + "، ".join(threat_names), "Google Web Risk"))
        score = 100

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        indicators.append(_indicator("ip_host", "استخدام عنوان IP كاسم للمضيف", 25,
                                      "يستخدم الرابط عنوان IP مباشرة بدلاً من نطاق مسجل"))
        try:
            address = ipaddress.ip_address(host)
            if not address.is_global:
                indicators.append(_indicator("non_global_ip", "عنوان IP غير عام", 35,
                                              "عنوان المضيف ليس عنوان IP عاماً قابلاً للتوجيه"))
        except ValueError:
            pass

    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        indicators.append(_indicator("userinfo", "مكوّن معلومات مستخدم مضلل", 35,
                                      "يحتوي الرابط على بيانات اعتماد أو رمز @ ضمن جزء اسم المضيف"))

    if "xn--" in host:
        indicators.append(_indicator("punycode", "ترميز نطاق دولي", 10,
                                      "يحتوي اسم المضيف على جزء بترميز Punycode؛ يُنصح بالتحقق من الأحرف المتشابهة"))

    shortener = host in SHORTENERS or any(host.endswith("." + item) for item in SHORTENERS)
    if shortener:
        indicators.append(_indicator("shortener", "رابط مختصر لم يُكشف عن وجهته", 10,
                                      "لم يتم تحديد الوجهة النهائية في وضع التحليل الآمن هذا"))

    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        indicators.append(_indicator("uncommon_tld", "نطاق علوي ضمن قائمة التحذير", 10,
                                      "يظهر هذا النطاق العلوي في قائمة التحذير بالمشروع، ولا يثبت ذلك وجود احتيال"))

    if host.count(".") >= 4:
        indicators.append(_indicator("many_subdomains", "بنية نطاق فرعي متداخلة على نحو غير معتاد", 8,
                                      "يحتوي اسم المضيف على أربع نقاط أو أكثر"))

    if sum(ch.isdigit() for ch in _root_label(registered_domain)) >= 2:
        indicators.append(_indicator("digit_heavy_domain", "أرقام في النطاق المسجل", 8,
                                      "تظهر عدة أرقام في اسم النطاق المسجل"))

    path_lower = (parsed.path or "").lower()
    if any(path_lower.endswith(ext) for ext in RISKY_EXTENSIONS):
        indicators.append(_indicator("risky_file_extension", "ملف قابل للتنزيل قد يكون خطراً", 25,
                                      "ينتهي مسار الرابط بنوع ملف يُستخدم غالباً لتوزيع ملفات تنفيذية"))

    host_tokens = re.split(r"[.-]", _root_label(registered_domain))
    matched_words = sorted(set(host_tokens) & SUSPICIOUS_HOST_WORDS)
    if matched_words:
        indicators.append(_indicator("suspicious_host_terms", "مصطلحات حساسة في النطاق", 8,
                                      "تتضمن أجزاء النطاق: " + "، ".join(matched_words)))

    arabic_found = sorted(term for term in ARABIC_SCAM_TERMS if term in (parsed.path + "?" + parsed.query))
    if len(arabic_found) >= 2:
        indicators.append(_indicator("arabic_payment_terms", "عبارات دفع أو تحقق عربية في الرابط", 8,
                                      "يتضمن الرابط: " + "، ".join(arabic_found)))

    redirect_targets = _extract_redirect_targets(parsed)
    if redirect_targets:
        indicators.append(_indicator("external_redirect_parameter", "الرابط يتضمن وجهة إعادة توجيه خارجية", 15,
                                      "تشير معلمة إعادة التوجيه إلى رابط آخر؛ ويُحلل الرابط المستهدف بشكل منفصل"))
        for target in redirect_targets:
            try:
                _, target_host, _ = _normalise_url(target)
                target_brand = detect_brand_impersonation(target_host)
                if target_brand["detected"]:
                    indicators.append(_indicator("redirect_brand_impersonation", "وجهة إعادة التوجيه تحاكي علامة محمية", 45,
                                                  target_brand["brand"] + " على " + target_host))
            except ValueError:
                pass

    if brand_result["detected"]:
        indicators.append(_indicator("brand_impersonation", "اشتباه انتحال علامة تجارية", 65,
                                      brand_result["brand"] + " — " + host))

    # Optional age check: informational unless the registry reports a recent registration.
    rdap = _check_rdap_domain_age(registered_domain, enable_rdap and not is_ip)
    if rdap["status"] == "available":
        intel.append({"provider": "RDAP", **rdap})
        if rdap["age_days"] < 30:
            indicators.append(_indicator("new_domain", "نطاق حديث التسجيل", 15,
                                          "عمر تسجيل النطاق وفق RDAP: " + str(rdap["age_days"]) + " يوماً", "RDAP"))
        elif rdap["age_days"] < 90:
            indicators.append(_indicator("young_domain", "نطاق حديث نسبياً", 8,
                                          "عمر تسجيل النطاق وفق RDAP: " + str(rdap["age_days"]) + " يوماً", "RDAP"))
    else:
        intel.append({"provider": "RDAP", **rdap})

    # A confirmed provider hit takes priority. Otherwise sum independent signals, capped at 100.
    if any(i["code"] in {"web_risk_match", "local_blocklist_match"} for i in indicators):
        score = 100
    else:
        score = min(99, sum(i["weight"] for i in indicators))

    if score >= 85:
        level, verdict = "critical", "confirmed_or_multiple_high_risk_signals"
        message = "مؤشرات خطورة عالية جداً — يُنصح بعدم فتح الرابط"
    elif score >= 60:
        level, verdict = "high", "suspicious"
        message = "اشتباه مرتفع — يُنصح بعدم فتح الرابط قبل التحقق"
    elif score >= 30:
        level, verdict = "medium", "suspicious"
        message = "اشتباه متوسط — يُنصح بالتحقق من الجهة عبر موقعها الرسمي"
    elif score > 0:
        level, verdict = "low", "needs_review"
        message = "مؤشرات محدودة — النتيجة غير حاسمة"
    else:
        level, verdict = "unknown", "no_strong_signals"
        message = "لم تظهر مؤشرات قوية، لكن هذا لا يؤكد أن الرابط آمن"

    if official_brand and score == 0:
        level, verdict = "low", "verified_official_domain_match"
        message = "النطاق يطابق نطاقاً رسمياً موثقاً في قائمة المشروع؛ يُنصح بالتحقق من الرابط الكامل قبل إدخال البيانات"

    # Each case carries a stable evidence reference and capture time. No site is opened.
    timestamp = _now_iso()
    case_id = uuid.uuid4().hex[:12].upper()
    evidence_hash = hashlib.sha256((normalized + "|" + timestamp).encode("utf-8")).hexdigest()

    return {
        "case_id": case_id,
        "analysis_timestamp_utc": timestamp,
        "submitted_url": raw_url,
        "normalized_url": normalized,
        "source": source,
        "hostname": host,
        "registered_domain": registered_domain,
        "risk_score": score,
        "risk_level": level,
        "verdict": verdict,
        "decision_ar": message,
        "brand_impersonation": brand_result,
        "verified_official_domain": official_domain,
        "indicators": indicators,
        "threat_intelligence": intel,
        "shortened_url": shortener,
        "redirect_targets_found": redirect_targets,
        "domain_registration": rdap,
        "evidence_sha256": evidence_hash,
        "limitations": [
            "لا يُفتح الموقع المستهدف ولا تُعرض صفحته أثناء هذا التحليل.",
            "لا يتم تلقائياً كشف وجهة الروابط المختصرة في هذه النسخة الأولية.",
            "عدم العثور على تطابق لا يثبت أن الموقع آمن.",
            "يتطلب اكتشاف إخفاء المحتوى والتشابه البصري مرحلة متصفح أو بيئة اختبار مضبوطة.",
        ],
    }


def load_local_blocklist(path: str) -> set[str]:
    values = set()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                item = line.strip()
                if item and not item.startswith("#"):
                    values.add(item.lower())
    except FileNotFoundError:
        pass
    return values


def set_local_blocklist(values):
    global LOCAL_BAD_URLS
    LOCAL_BAD_URLS = {str(item).strip().lower() for item in values if str(item).strip()}
