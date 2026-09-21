import re

# Keywords that strongly indicate a credential phishing page when in the URL path
_PHISH_URL_KEYWORDS = re.compile(
    r'(login|signin|sign-in|verify|verification|account|secure|security|update|'
    r'confirm|auth|credential|authenticate|password|passwd|recover|unlock|suspend)',
    re.IGNORECASE
)


def calculate_risk_scorecard(url: str, ml_prob: float, extracted_features: dict,
                              ti_data: dict, brand_data: dict = None,
                              attack_data: dict = None) -> dict:
    """
    Weighted evidence-based risk scoring engine.
    A single weak signal CANNOT classify a URL as dangerous.
    Multiple corroborating signals are required.
    Trusted domains are hard-capped to prevent false positives.
    """
    score = 0.0
    url_lower = url.lower()

    # ── TRUST FAST-PATH ──────────────────────────────────────────────────────
    # If the domain is in our trusted registry AND has no payload signals,
    # short-circuit immediately – no need to score further.
    is_trusted = bool(extracted_features.get("is_trusted_domain"))
    has_payload = bool(
        extracted_features.get("has_script_payload") or
        extracted_features.get("has_homoglyph_spoof") or
        extracted_features.get("has_malformed_chars")
    )
    if is_trusted and not has_payload:
        # Trusted domain with zero payload threats → always SAFE
        overall_risk = min(10, int(ml_prob * 10))
        confidence   = min(0.99, 0.97 + (0.02 * (1.0 - overall_risk / 10)))
        return _build_scorecard(overall_risk, confidence, extracted_features,
                                ti_data, brand_data, is_phish_hit=False, ti_hit=False)

    # ── WEIGHT ACCUMULATION ─────────────────────────────────────────────────

    ti_hit    = False
    brand_hit = False

    # 1. Threat Intelligence Match (Weight: 35)
    if ti_data:
        vt_hits = ti_data.get("virustotal", {}).get("detections", 0)
        if ti_data.get("phishtank") or ti_data.get("openphish") or \
                ti_data.get("urlhaus") or vt_hits > 0:
            score += 35
            ti_hit = True

    # 2. Brand Impersonation (Weight: 40)
    if (brand_data and brand_data.get("is_impersonation")) or \
            extracted_features.get("brand_impersonation"):
        score += 40
        brand_hit = True

    # 3. Risky TLD (Weight: 20)
    if extracted_features.get("is_risky_tld"):
        score += 20

    # 4. No HTTPS / Plaintext HTTP (Weight: 10)
    if not extracted_features.get("has_https"):
        score += 10

    # 5. Credential / Phishing URL keywords in path (Weight: 15)
    if _PHISH_URL_KEYWORDS.search(url_lower):
        score += 15

    # 6. ML Model Confidence (Weight: up to 30)
    if ml_prob > 0.85:
        score += 30
    elif ml_prob > 0.65:
        score += 20
    elif ml_prob > 0.50:
        score += 10

    # 7. Scam keywords / Script payloads (Weight: 20)
    if extracted_features.get("has_scam_keywords") or \
            extracted_features.get("has_script_payload"):
        score += 20

    # 8. Homoglyph Attack (Weight: 20)
    if extracted_features.get("has_homoglyph_spoof"):
        score += 20

    # 9. Malformed characters (Weight: 15)
    if extracted_features.get("has_malformed_chars"):
        score += 15

    # 10. Suspicious Redirects (Weight: 15)
    if extracted_features.get("has_redirect_params"):
        score += 15

    # 11. High Entropy (Weight: 10)
    if extracted_features.get("domain_entropy", 0) > 4.0 or \
            extracted_features.get("query_entropy", 0) > 4.5:
        score += 10

    # 12. Structural signals (lightweight)
    if extracted_features.get("url_length", 0) > 75:
        score += 5
    if extracted_features.get("hyphen_count", 0) > 3:
        score += 3
    if extracted_features.get("dot_count", 0) > 3:
        score += 2

    # ── INSTITUTIONAL TLD MITIGATION ────────────────────────────────────────
    if extracted_features.get("is_institutional_tld"):
        score = min(score, 25)

    overall_risk = min(100, int(score))

    # ── CONFIDENCE CALIBRATION ──────────────────────────────────────────────
    if is_trusted and overall_risk <= 15:
        confidence = 0.99
    elif ti_hit and overall_risk >= 85:
        confidence = min(0.99, 0.97 + 0.02 * (overall_risk / 100))
    elif brand_hit and overall_risk >= 71:
        confidence = 0.95
    elif overall_risk >= 71 and ml_prob >= 0.60:
        confidence = 0.90 + 0.09 * ml_prob
    elif overall_risk <= 25 and ml_prob <= 0.30:
        confidence = 0.85 + 0.10 * (1.0 - ml_prob)
    else:
        confidence = 0.60 + 0.30 * ml_prob

    confidence = min(0.99, max(0.50, confidence))

    return _build_scorecard(overall_risk, confidence, extracted_features,
                            ti_data, brand_data, brand_hit, ti_hit)


def _build_scorecard(overall_risk, confidence, extracted_features,
                     ti_data, brand_data, is_phish_hit, ti_hit):
    return {
        "overall_risk":             overall_risk,
        "confidence":               confidence,
        "domain_reputation":        (0 if extracted_features.get("is_trusted_domain")
                                     else 80 if extracted_features.get("is_risky_tld")
                                     else 20),
        "url_structure":            min(100, int(
                                        (extracted_features.get("url_length", 0) / 150) * 100)),
        "keyword_risk":             90 if extracted_features.get("has_scam_keywords") else 10,
        "brand_impersonation":      85 if is_phish_hit else 5,
        "ssl_trust":                5 if extracted_features.get("has_https") else 75,
        "threat_intelligence_match": 100 if ti_hit else 0,
        "entropy_score":            min(100, int(
                                        extracted_features.get("domain_entropy", 0) * 20)),
        "redirect_risk":            90 if extracted_features.get("has_redirect_params") else 10,
        "homoglyph_risk":           95 if extracted_features.get("has_homoglyph_spoof") else 5,
        "script_injection_risk":    99 if extracted_features.get("has_script_payload") else 0,
        "obfuscation_score":        min(100, int(
                                        extracted_features.get("query_entropy", 0) * 20)),
    }
