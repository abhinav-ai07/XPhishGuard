"""
XPhishGuard AI — Phase 1.6 Prediction Engine
============================================

Hybrid scoring now includes anomaly escalation and payload validation.
Trusted domains (like youtube.com or google.com) NO LONGER receive automatic
bypasses if their payload is malformed or contains script injection vectors.
"""

import os
import pickle
import numpy as np
import pandas as pd
import urllib.parse

from feature_engineering import extract_features, get_feature_list

_MODEL_CACHE = None

FEATURE_NAMES = [
    "url_length", "dot_count", "hyphen_count", "has_https",
    "has_at_symbol", "is_ip_address", "is_risky_tld", "brand_impersonation",
    "domain_entropy", "digit_ratio", "subdomain_count", "token_count",
    "keyword_density", "is_shortened", "has_redirect_params",
    "has_scam_keywords", "is_trusted_domain", "is_institutional_tld",
    "is_search_engine", "is_ai_platform", "is_streaming_platform",
    "is_coding_platform", "is_educational_platform", "is_social_platform",
    # Phase 1.6
    "has_malformed_chars", "special_char_ratio", "query_entropy",
    "has_script_payload", "has_homoglyph_spoof"
]

def get_model():
    global _MODEL_CACHE
    if _MODEL_CACHE is None:
        backend_dir = os.path.dirname(os.path.abspath(__file__))
        model_path  = os.path.join(backend_dir, "models", "phishing_model.pkl")
        if not os.path.exists(model_path):
            raise FileNotFoundError("Model not found. Run: python backend/train_model.py")
        with open(model_path, "rb") as f:
            _MODEL_CACHE = pickle.load(f)
    return _MODEL_CACHE


def _hybrid_score(raw_prob: float, feats: dict) -> tuple[float, list[str]]:
    signals = []
    prob = raw_prob

    # ── LAYER 0: Obfuscation / Payload Escalation (Overrides Trust) ──
    # If a payload is malicious, it doesn't matter if it's hosted on a trusted domain.
    # We flag these early so they bypass the trust reduction layer below.
    is_payload_malicious = False
    
    if feats.get("has_script_payload"):
        signals.append("Script Injection / XSS Detected")
        prob = max(0.99, prob + 0.80)
        is_payload_malicious = True
        
    if feats.get("has_malformed_chars"):
        signals.append("Malformed / Illegal Characters")
        prob = min(1.0, prob + 0.60)
        is_payload_malicious = True
        
    if feats.get("has_homoglyph_spoof"):
        signals.append("Homoglyph / Visual Spoofing")
        prob = min(1.0, prob + 0.50)
        is_payload_malicious = True
        
    if feats.get("query_entropy", 0) > 4.5:
        signals.append("High Query Entropy (Obfuscation)")
        prob = min(1.0, prob + 0.20)
        is_payload_malicious = True
        
    if feats.get("special_char_ratio", 0) > 0.35:
        signals.append("High Special Character Density")
        prob = min(1.0, prob + 0.20)
        is_payload_malicious = True

    # ── LAYER 1: Trust ───────────────────────────────────
    # We only apply trust reductions if the payload is CLEAN.
    if not is_payload_malicious:
        if feats.get("is_trusted_domain"):
            signals.append("Trusted Domain")
            return min(0.05, prob * 0.05), signals

        if feats.get("is_institutional_tld"):
            signals.append("Institutional TLD (.edu/.gov)")
            return min(0.08, prob * 0.08), signals

        category_hits = []
        if feats.get("is_search_engine"):       category_hits.append("Search Engine")
        if feats.get("is_ai_platform"):         category_hits.append("AI Platform")
        if feats.get("is_streaming_platform"):  category_hits.append("Streaming Platform")
        if feats.get("is_coding_platform"):     category_hits.append("Coding Platform")
        if feats.get("is_educational_platform"):category_hits.append("Educational Platform")
        if feats.get("is_social_platform"):     category_hits.append("Social Platform")

        if category_hits:
            signals.extend(category_hits)
            prob *= 0.25

    # ── LAYER 2: Risk amplification (for untrusted/malicious domains) ──
    if feats.get("is_risky_tld"):
        signals.append("Risky TLD")
        prob = min(1.0, prob + 0.35)

    if feats.get("brand_impersonation"):
        signals.append("Brand Impersonation / Typosquatting")
        prob = min(1.0, prob + 0.30)

    if feats.get("has_scam_keywords"):
        signals.append("Scam Keywords Detected")
        prob = min(1.0, prob + 0.15)

    return min(1.0, max(0.0, prob)), signals


def _risk_level(prob: float) -> str:
    if prob < 0.30: return "LOW"
    if prob < 0.60: return "MEDIUM"
    return "HIGH"


def predict_url(url: str) -> dict:
    # 0. Sanitization
    sanitized_url = urllib.parse.unquote(url.strip())
    
    # 1. Extraction
    feats_dict   = extract_features(sanitized_url)
    feats_vector = get_feature_list(sanitized_url)

    X = pd.DataFrame([feats_vector], columns=FEATURE_NAMES)
    model = get_model()
    raw_prob = float(model.predict_proba(X)[0][1])

    # 2. Hybrid scoring
    adj_prob, signals = _hybrid_score(raw_prob, feats_dict)

    return {
        "url":               sanitized_url,
        "is_phishing":       adj_prob > 0.50,
        "confidence_score":  adj_prob,
        "risk_level":        _risk_level(adj_prob),
        "triggered_signals": signals,
        "confidence":        adj_prob,
        "features":          feats_dict,
    }
