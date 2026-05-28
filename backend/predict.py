"""
XPhishGuard AI — Phase 1.5 Prediction Engine with Hybrid Scoring
=================================================================

Architecture:
    Raw URL
      │
      ├─► Feature Extraction (24-dim vector)
      │
      ├─► XGBoost Inference  →  raw_phishing_probability
      │
      ├─► Hybrid Reputation Engine  →  adjusted_probability
      │         ├─ TRUST layer  (is_trusted_domain, institutional_tld, category)
      │         └─ RISK  layer  (risky_tld, brand_spoof, scam keywords)
      │
      └─► Final verdict  (is_phishing, confidence, risk_level)

WHY A HYBRID ENGINE:
  Pure ML on lexical features suffers from shortcut learning.
  Enterprise products (e.g., Cisco Umbrella, Palo Alto DNS Security)
  layer ML scores with reputation feeds, allowlists, and domain-category
  intelligence. This file implements a lightweight version of that pattern.
"""

import os
import pickle
import numpy as np
import pandas as pd

from feature_engineering import extract_features, get_feature_list

# ─────────────────────────────────────────────────────────
#  MODEL CACHE  (singleton loader)
# ─────────────────────────────────────────────────────────

_MODEL_CACHE = None

FEATURE_NAMES = [
    "url_length", "dot_count", "hyphen_count", "has_https",
    "has_at_symbol", "is_ip_address", "is_risky_tld", "brand_impersonation",
    "domain_entropy", "digit_ratio", "subdomain_count", "token_count",
    "keyword_density", "is_shortened", "has_redirect_params",
    "has_scam_keywords", "is_trusted_domain", "is_institutional_tld",
    "is_search_engine", "is_ai_platform", "is_streaming_platform",
    "is_coding_platform", "is_educational_platform", "is_social_platform",
]


def get_model():
    global _MODEL_CACHE
    if _MODEL_CACHE is None:
        backend_dir = os.path.dirname(os.path.abspath(__file__))
        model_path  = os.path.join(backend_dir, "models", "phishing_model.pkl")
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model not found at '{model_path}'. "
                "Run: python backend/train_model.py"
            )
        with open(model_path, "rb") as f:
            _MODEL_CACHE = pickle.load(f)
    return _MODEL_CACHE


# ─────────────────────────────────────────────────────────
#  HYBRID REPUTATION SCORING ENGINE
# ─────────────────────────────────────────────────────────

def _hybrid_score(raw_prob: float, feats: dict) -> tuple[float, list[str]]:
    """
    Applies layered reputation adjustments to the raw ML phishing probability.

    Returns (adjusted_probability, list_of_triggered_signals)

    LAYER 1 — TRUST (overrides everything, returns early):
      Trusted root domain   → cap probability at 0.05
      Institutional TLD     → cap probability at 0.08
      Category membership   → multiply by 0.25

    LAYER 2 — RISK AMPLIFICATION (only for untrusted domains):
      Risky TLD             → +0.35
      Brand impersonation   → +0.30
      Scam keywords         → +0.15
    """
    signals = []
    prob = raw_prob

    # ── LAYER 1: Trust ───────────────────────────────────
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

    # ── LAYER 2: Risk amplification ──────────────────────
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
    if prob < 0.30:
        return "LOW"
    if prob < 0.60:
        return "MEDIUM"
    return "HIGH"


# ─────────────────────────────────────────────────────────
#  MAIN PREDICTION FUNCTION
# ─────────────────────────────────────────────────────────

def predict_url(url: str) -> dict:
    """
    Full inference pipeline: feature extraction → ML → hybrid scoring.

    Returns:
    {
        url, is_phishing, confidence_score, risk_level,
        triggered_signals, extracted_features
    }
    """
    # 1. Extract features
    feats_dict   = extract_features(url)
    feats_vector = get_feature_list(url)

    # 2. Build DataFrame (preserves feature names for XGBoost)
    X = pd.DataFrame(
        np.array(feats_vector).reshape(1, -1),
        columns=FEATURE_NAMES
    )

    # 3. ML inference
    model     = get_model()
    raw_prob  = float(model.predict_proba(X)[0][1])  # P(phishing)

    # 4. Hybrid reputation scoring
    adj_prob, signals = _hybrid_score(raw_prob, feats_dict)

    return {
        "url":               url,
        "is_phishing":       adj_prob > 0.50,
        "confidence_score":  adj_prob,
        "risk_level":        _risk_level(adj_prob),
        "triggered_signals": signals,
        "confidence":        adj_prob,           # legacy key kept for main.py
        "features":          feats_dict,         # legacy key kept for main.py
    }


# ─────────────────────────────────────────────────────────
#  INTERACTIVE CLI  (python predict.py)
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n=== XPhishGuard AI — Phase 1.5 Detector ===\n")
    while True:
        url = input("Enter URL (or 'exit'): ").strip()
        if url.lower() == "exit":
            break
        try:
            r = predict_url(url)
            verdict = "PHISHING" if r["is_phishing"] else "SAFE"
            print(f"\n  Verdict       : {verdict}")
            print(f"  Risk Level    : {r['risk_level']}")
            print(f"  Confidence    : {r['confidence_score']*100:.1f}%")
            print(f"  Signals       : {', '.join(r['triggered_signals']) or 'none'}")
            print()
        except Exception as e:
            print(f"  ERROR: {e}\n")
