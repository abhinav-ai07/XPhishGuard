"""
XPhishGuard AI — Phase 4 Threat Intelligence Integration Layer
=================================================================

Integrates live threat feeds (VirusTotal, PhishTank, OpenPhish, URLHaus)
with the SHAP-based ML classifier and hybrid heuristics. Provides concise,
analyst-style explanations capped at 5 points.
"""

import os
import pickle
import numpy as np
import pandas as pd
import urllib.parse
import io
import base64

# Force matplotlib headless backend
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import shap

from feature_engineering import extract_features, get_feature_list
from threat_intel import get_threat_intelligence, calculate_threat_intel_boost

_MODEL_CACHE = None
_EXPLAINER_CACHE = None

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

# Short and direct analyst-style templates (Phase 4 Requirement)
HUMAN_EXPLANATION_TEMPLATES = {
    "url_length": {
        "positive": "Long URL detected.",
        "negative": "Standard URL length."
    },
    "dot_count": {
        "positive": "Excessive dots in domain.",
        "negative": "Standard dot frequency."
    },
    "hyphen_count": {
        "positive": "Excessive hyphens in domain.",
        "negative": "Standard hyphen frequency."
    },
    "has_https": {
        "positive": "HTTPS protocol active.",
        "negative": "Unsecured HTTP connection."
    },
    "has_at_symbol": {
        "positive": "Redirection character (@) detected.",
        "negative": "No suspicious redirection symbols."
    },
    "is_ip_address": {
        "positive": "Raw IP address used.",
        "negative": "Standard domain host."
    },
    "is_risky_tld": {
        "positive": "Risky TLD detected.",
        "negative": "Standard TLD registry."
    },
    "brand_impersonation": {
        "positive": "Brand impersonation detected.",
        "negative": "No brand impersonation detected."
    },
    "domain_entropy": {
        "positive": "High domain entropy.",
        "negative": "Standard domain entropy."
    },
    "digit_ratio": {
        "positive": "High ratio of digits.",
        "negative": "Standard digit ratio."
    },
    "subdomain_count": {
        "positive": "Excessive subdomains.",
        "negative": "Standard subdomain structure."
    },
    "token_count": {
        "positive": "Excessive URL path tokens.",
        "negative": "Standard path structure."
    },
    "keyword_density": {
        "positive": "Suspicious keywords present.",
        "negative": "No suspicious keywords detected."
    },
    "is_shortened": {
        "positive": "Shortened URL link.",
        "negative": "No redirection shorteners."
    },
    "has_redirect_params": {
        "positive": "Redirect parameters present.",
        "negative": "No open redirect vectors."
    },
    "has_scam_keywords": {
        "positive": "Scam keywords present.",
        "negative": "No scam keywords detected."
    },
    "is_trusted_domain": {
        "positive": "Trusted domain matched.",
        "negative": "Untrusted domain."
    },
    "is_institutional_tld": {
        "positive": "Institutional TLD matched.",
        "negative": "Non-institutional TLD."
    },
    "is_search_engine": {
        "positive": "Verified search engine.",
        "negative": "Non-search host."
    },
    "is_ai_platform": {
        "positive": "Verified AI platform.",
        "negative": "Non-AI host."
    },
    "is_streaming_platform": {
        "positive": "Verified streaming host.",
        "negative": "Non-streaming host."
    },
    "is_coding_platform": {
        "positive": "Verified repository host.",
        "negative": "Non-code repository."
    },
    "is_educational_platform": {
        "positive": "Verified educational host.",
        "negative": "Non-educational host."
    },
    "is_social_platform": {
        "positive": "Verified social network.",
        "negative": "Non-social network."
    },
    "has_malformed_chars": {
        "positive": "Malformed payload characters.",
        "negative": "No malformed symbols."
    },
    "special_char_ratio": {
        "positive": "High special character density.",
        "negative": "Standard special character density."
    },
    "query_entropy": {
        "positive": "High query string entropy.",
        "negative": "Standard query entropy."
    },
    "has_script_payload": {
        "positive": "Script payload detected.",
        "negative": "No active script payloads."
    },
    "has_homoglyph_spoof": {
        "positive": "Homoglyph brand spoof detected.",
        "negative": "No character spoofing."
    }
}


def get_model_and_explainer():
    global _MODEL_CACHE, _EXPLAINER_CACHE
    if _MODEL_CACHE is None:
        backend_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(backend_dir, "models", "phishing_model.pkl")
        if not os.path.exists(model_path):
            raise FileNotFoundError("Model not found. Run: python backend/train_model.py")
        with open(model_path, "rb") as f:
            _MODEL_CACHE = pickle.load(f)
        
        # Initialize SHAP explainer
        print("Initializing SHAP TreeExplainer for champion model...")
        _EXPLAINER_CACHE = shap.TreeExplainer(_MODEL_CACHE)
        
    return _MODEL_CACHE, _EXPLAINER_CACHE


def _hybrid_score_tracked(raw_prob: float, feats: dict) -> tuple[float, list[str], dict]:
    """
    Applies the hybrid cybersecurity engine's rules and tracks probability alterations
    contributed by each rule, returning final adjusted probability, list of signals,
    and a dict mapping feature names to their exact probability delta.
    """
    signals = []
    prob = raw_prob
    rule_adjustments = {}

    def apply_adj(feature_name, new_prob, signal_msg):
        nonlocal prob
        delta = new_prob - prob
        if abs(delta) > 1e-5:
            rule_adjustments[feature_name] = rule_adjustments.get(feature_name, 0.0) + delta
            prob = new_prob
            signals.append(signal_msg)

    # ── LAYER 0: Obfuscation / Payload Escalation (Overrides Trust) ──
    is_payload_malicious = False
    
    if feats.get("has_script_payload"):
        apply_adj("has_script_payload", max(0.99, prob + 0.80), "Script Injection / XSS Detected")
        is_payload_malicious = True
        
    if feats.get("has_malformed_chars"):
        apply_adj("has_malformed_chars", min(1.0, prob + 0.60), "Malformed / Illegal Characters")
        is_payload_malicious = True
        
    if feats.get("has_homoglyph_spoof"):
        apply_adj("has_homoglyph_spoof", min(1.0, prob + 0.50), "Homoglyph / Visual Spoofing")
        is_payload_malicious = True
        
    if feats.get("query_entropy", 0) > 4.5:
        apply_adj("query_entropy", min(1.0, prob + 0.20), "High Query Entropy (Obfuscation)")
        is_payload_malicious = True
        
    if feats.get("special_char_ratio", 0) > 0.35:
        apply_adj("special_char_ratio", min(1.0, prob + 0.20), "High Special Character Density")
        is_payload_malicious = True

    # ── LAYER 1: Trust Reduction ──
    if not is_payload_malicious:
        if feats.get("is_trusted_domain"):
            apply_adj("is_trusted_domain", min(0.05, prob * 0.05), "Trusted Domain")
            return prob, signals, rule_adjustments

        if feats.get("is_institutional_tld"):
            apply_adj("is_institutional_tld", min(0.08, prob * 0.08), "Institutional TLD (.edu/.gov)")
            return prob, signals, rule_adjustments

        category_hits = []
        if feats.get("is_search_engine"):       category_hits.append(("is_search_engine", "Search Engine"))
        if feats.get("is_ai_platform"):         category_hits.append(("is_ai_platform", "AI Platform"))
        if feats.get("is_streaming_platform"):  category_hits.append(("is_streaming_platform", "Streaming Platform"))
        if feats.get("is_coding_platform"):     category_hits.append(("is_coding_platform", "Coding Platform"))
        if feats.get("is_educational_platform"):category_hits.append(("is_educational_platform", "Educational Platform"))
        if feats.get("is_social_platform"):     category_hits.append(("is_social_platform", "Social Platform"))

        if category_hits:
            target_prob = prob * 0.25
            total_reduction = target_prob - prob
            reduction_per_cat = total_reduction / len(category_hits)
            for feat_name, sig_msg in category_hits:
                rule_adjustments[feat_name] = rule_adjustments.get(feat_name, 0.0) + reduction_per_cat
                signals.append(sig_msg)
            prob = target_prob

    # ── LAYER 2: Risk Amplification (for untrusted/malicious domains) ──
    if feats.get("is_risky_tld"):
        apply_adj("is_risky_tld", min(1.0, prob + 0.35), "Risky TLD")

    if feats.get("brand_impersonation"):
        apply_adj("brand_impersonation", min(1.0, prob + 0.30), "Brand Impersonation / Typosquatting")

    if feats.get("has_scam_keywords"):
        apply_adj("has_scam_keywords", min(1.0, prob + 0.15), "Scam Keywords Detected")

    return min(1.0, max(0.0, prob)), signals, rule_adjustments


def _risk_level(prob: float) -> str:
    if prob < 0.30: return "LOW"
    if prob < 0.60: return "MEDIUM"
    return "HIGH"


def generate_analyst_summary(feats_dict, is_phishing, confidence, risk_level, triggered_signals, ti_data):
    if is_phishing:
        summary = f"URL flagged as PHISHING with a confidence score of {confidence*100:.1f}% ({risk_level} Risk). "
        
        # Threat intel matching
        feeds_hit = []
        if ti_data.get("phishtank"): feeds_hit.append("PhishTank")
        if ti_data.get("openphish"): feeds_hit.append("OpenPhish")
        if ti_data.get("urlhaus"): feeds_hit.append("URLHaus")
        if ti_data.get("virustotal", {}).get("detections", 0) > 20: 
            feeds_hit.append(f"VirusTotal ({ti_data['virustotal']['detections']} detections)")
            
        if feeds_hit:
            summary += f"Blacklisted in active feeds: {', '.join(feeds_hit)}. "
            
        reasons = []
        if feats_dict.get("brand_impersonation"):
            reasons.append("brand impersonation")
        if feats_dict.get("is_risky_tld"):
            reasons.append("risky TLD")
        if feats_dict.get("has_script_payload"):
            reasons.append("script injection payload")
        if feats_dict.get("has_homoglyph_spoof"):
            reasons.append("homoglyph brand spoofing")
            
        if reasons:
            summary += "Attack vectors: " + ", ".join(reasons) + "."
    else:
        summary = f"URL verified as SAFE. Confidence score: {(1-confidence)*100:.1f}% ({risk_level} Risk). "
        trusts = []
        if feats_dict.get("is_trusted_domain"):
            trusts.append("known trusted registry")
        if feats_dict.get("is_institutional_tld"):
            trusts.append("educational/gov TLD")
        if feats_dict.get("has_https"):
            trusts.append("HTTPS security")
            
        if trusts:
            summary += "Trust factors: " + " & ".join(trusts) + "."
            
    return summary


def build_threat_timeline(feats_dict, raw_prob, adj_prob, final_prob, triggered_signals, ti_triggers):
    timeline = []
    step = 1
    
    # 1. Lexical Analysis
    timeline.append({
        "step": step,
        "event": "Lexical Analysis",
        "details": f"Parsed URL length: {feats_dict['url_length']} chars, {feats_dict['subdomain_count']} subdomains."
    })
    step += 1
    
    # 2. Protocol Check
    protocol = "HTTPS (secure)" if feats_dict['has_https'] else "HTTP (unencrypted)"
    timeline.append({
        "step": step,
        "event": "Protocol Verification",
        "details": f"Protocol: {protocol}."
    })
    step += 1
    
    # 3. Threat Intelligence scan (Phase 4 addition)
    if len(ti_triggers) > 0:
        details_str = ", ".join([f"{sig} (+{boost*100:.0f}%)" for _, boost, sig in ti_triggers])
        timeline.append({
            "step": step,
            "event": "Threat Intelligence Lookup",
            "details": f"Blacklist hit: {details_str}."
        })
    else:
        timeline.append({
            "step": step,
            "event": "Threat Intelligence Lookup",
            "details": "Clean scan across VirusTotal, PhishTank, OpenPhish, and URLHaus."
        })
    step += 1
    
    # 4. Domain Reputation
    reps = []
    if feats_dict['is_trusted_domain']: reps.append("Trusted domain matched")
    if feats_dict['is_institutional_tld']: reps.append("Institutional TLD matched")
    if feats_dict['is_risky_tld']: reps.append("Risky TLD registry match")
    if reps:
        timeline.append({
            "step": step,
            "event": "Domain Reputation Check",
            "details": ", ".join(reps) + "."
        })
        step += 1
        
    # 5. Machine Learning Classification
    verdict = "PHISHING" if raw_prob > 0.5 else "SAFE"
    timeline.append({
        "step": step,
        "event": "ML Model Inference",
        "details": f"Model verdict: {verdict} (Raw probability: {raw_prob*100:.1f}%)."
    })
    step += 1
    
    # 6. Final Score Consolidation
    timeline.append({
        "step": step,
        "event": "Risk Heuristics & Threat Feed Merging",
        "details": f"Final probability calculated at {final_prob*100:.1f}%."
    })
        
    return timeline


def generate_local_plots(explainer, shap_values_obj, X, total_impacts, base_prob, adj_prob):
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    exp_dir = os.path.join(backend_dir, "explanations")
    os.makedirs(exp_dir, exist_ok=True)
    
    plot_data = {}
    
    # 1. Feature Importance Bar Chart
    try:
        plt.figure(figsize=(7, 3.5))
        FEATURE_NAMES = list(X.columns)
        contribs = total_impacts
        sorted_idx = np.argsort(np.abs(contribs))
        non_zero_idx = [i for i in sorted_idx if abs(contribs[i]) > 0.005][-8:]
        
        if len(non_zero_idx) > 0:
            names_to_plot = [FEATURE_NAMES[i] for i in non_zero_idx]
            vals_to_plot = [contribs[i] for i in non_zero_idx]
            colors = ['#EF4444' if x > 0 else '#3B82F6' for x in vals_to_plot]
            
            plt.barh(names_to_plot, vals_to_plot, color=colors)
            plt.title("Combined Feature Impact (ML + Rules + Threat Intel)", fontsize=10, fontweight='bold', pad=10)
            plt.xlabel("Impact on Phishing Risk Probability", fontsize=8)
            plt.axvline(x=0, color='grey', linestyle='--', linewidth=0.8)
            plt.gca().xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0))
            plt.tight_layout()
            
            plt.savefig(os.path.join(exp_dir, "local_importance.png"), dpi=150)
            
            buf = io.BytesIO()
            plt.savefig(buf, format='png', dpi=150)
            buf.seek(0)
            plot_data["local_importance"] = base64.b64encode(buf.read()).decode('utf-8')
        plt.close()
    except Exception as e:
        print("Error generating local_importance plot:", e)
        plt.close()
        
    # 2. SHAP Waterfall Plot
    try:
        plt.figure(figsize=(8, 3.5))
        shap.plots.waterfall(shap_values_obj[0], max_display=8, show=False)
        plt.title("ML Model Decision Waterfall (Log-Odds)", fontsize=10, fontweight='bold', pad=15)
        plt.tight_layout()
        
        plt.savefig(os.path.join(exp_dir, "waterfall.png"), dpi=150)
        
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150)
        buf.seek(0)
        plot_data["waterfall"] = base64.b64encode(buf.read()).decode('utf-8')
        plt.close()
    except Exception as e:
        print("Error generating waterfall plot:", e)
        plt.close()
        
    # 3. SHAP Force Plot
    try:
        plt.figure(figsize=(10, 2.5))
        expected_val = explainer.expected_value
        if isinstance(expected_val, (list, np.ndarray)):
            expected_val = expected_val[1] if len(expected_val) > 1 else expected_val[0]
            
        shap.plots.force(expected_val, shap_values_obj.values[0], X.iloc[0], matplotlib=True, show=False)
        plt.title("ML Model Decision Force Plot (Log-Odds)", fontsize=10, fontweight='bold', pad=15)
        plt.tight_layout()
        
        plt.savefig(os.path.join(exp_dir, "force.png"), dpi=150)
        
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=150)
        buf.seek(0)
        plot_data["force"] = base64.b64encode(buf.read()).decode('utf-8')
        plt.close()
    except Exception as e:
        print("Error generating force plot:", e)
        plt.close()
        
    return plot_data


def predict_url(url: str) -> dict:
    # 0. Sanitization
    sanitized_url = urllib.parse.unquote(url.strip())
    
    # ── PHASE 4 STEP 1: Threat Intelligence Layer ──
    ti_data = get_threat_intelligence(sanitized_url)
    ti_boost, ti_triggers = calculate_threat_intel_boost(ti_data)

    # ── PHASE 4 STEP 2: ML Engine ──
    feats_dict = extract_features(sanitized_url)
    feats_vector = get_feature_list(sanitized_url)

    X = pd.DataFrame([feats_vector], columns=FEATURE_NAMES)
    model, explainer = get_model_and_explainer()
    
    raw_prob = float(model.predict_proba(X)[0][1])

    # ── PHASE 4 STEP 3: Hybrid Risk Scoring ──
    adj_prob, signals, rule_adjustments = _hybrid_score_tracked(raw_prob, feats_dict)

    # ── PHASE 4 STEP 4: Merge Threat Intel ──
    final_prob = min(1.0, max(0.0, adj_prob + ti_boost))

    # SHAP local calculations
    shap_values_obj = explainer(X)
    shap_values = shap_values_obj.values[0]
    
    expected_val = explainer.expected_value
    if isinstance(expected_val, (list, np.ndarray)):
        expected_val = expected_val[1] if len(expected_val) > 1 else expected_val[0]

    # Convert SHAP log-odds contributions to probability-space impacts
    base_prob = 1.0 / (1.0 + np.exp(-expected_val))
    diff = raw_prob - base_prob
    sum_shap = np.sum(shap_values)
    
    if abs(sum_shap) < 1e-6:
        ml_impacts = np.zeros_like(shap_values)
    else:
        scale = diff / sum_shap
        ml_impacts = shap_values * scale

    # Merge ML SHAP impacts, rule-based adjustments, and Threat Intel boosts
    total_impacts = np.zeros_like(ml_impacts)
    for i, name in enumerate(FEATURE_NAMES):
        total_impacts[i] = ml_impacts[i] + rule_adjustments.get(name, 0.0)

    # Create top contributors including threat intelligence triggers
    top_contributors = []
    # Add threat intel boosts to contributors
    for feat_name, boost_val, sig_msg in ti_triggers:
        top_contributors.append({
            "feature": feat_name,
            "impact": f"+{boost_val*100:.0f}%",
            "raw_impact": boost_val
        })

    # Add standard ML + heuristic feature contributions
    for name, impact in zip(FEATURE_NAMES, total_impacts):
        if abs(impact) > 0.005:
            sign = "+" if impact > 0 else ""
            top_contributors.append({
                "feature": name,
                "impact": f"{sign}{impact*100:.1f}%",
                "raw_impact": float(impact)
            })
            
    # Sort descending by absolute impact
    top_contributors = sorted(top_contributors, key=lambda x: abs(x["raw_impact"]), reverse=True)

    # Human Friendly Explanations (Short and Direct - Phase 4)
    human_explanations = []
    
    # Add threat intel matches to explanations
    for feat_name, boost_val, sig_msg in ti_triggers:
        if feat_name == "phishtank_match": msg = "PhishTank blacklist hit."
        elif feat_name == "openphish_match": msg = "OpenPhish blacklist hit."
        elif feat_name == "virustotal_detections": msg = f"VirusTotal Alert ({ti_data['virustotal']['detections']} detections)."
        elif feat_name == "urlhaus_match": msg = "URLHaus malware hit."
        
        human_explanations.append({
            "feature": feat_name,
            "impact_type": "RISK_FACTOR",
            "impact_percent": f"+{boost_val*100:.0f}%",
            "message": msg
        })

    # Add standard feature explanations based on thresholds
    for name, impact in zip(FEATURE_NAMES, total_impacts):
        val = feats_dict[name]
        is_triggered = False
        if name in [
            "has_https", "has_at_symbol", "is_ip_address", "is_risky_tld", "brand_impersonation", 
            "is_shortened", "has_redirect_params", "has_scam_keywords", "is_trusted_domain", 
            "is_institutional_tld", "is_search_engine", "is_ai_platform", "is_streaming_platform", 
            "is_coding_platform", "is_educational_platform", "is_social_platform", "has_malformed_chars", 
            "has_script_payload", "has_homoglyph_spoof"
        ]:
            if val == 1: is_triggered = True
        else:
            if name == "url_length" and val > 75: is_triggered = True
            elif name == "dot_count" and val > 3: is_triggered = True
            elif name == "hyphen_count" and val > 2: is_triggered = True
            elif name == "domain_entropy" and val > 3.8: is_triggered = True
            elif name == "digit_ratio" and val > 0.2: is_triggered = True
            elif name == "subdomain_count" and val > 2: is_triggered = True
            elif name == "token_count" and val > 5: is_triggered = True
            elif name == "keyword_density" and val > 0.1: is_triggered = True
            elif name == "special_char_ratio" and val > 0.2: is_triggered = True
            elif name == "query_entropy" and val > 4.0: is_triggered = True

        if is_triggered or abs(impact) > 0.02:
            templates = HUMAN_EXPLANATION_TEMPLATES.get(name)
            if templates:
                is_pos = False
                if name in [
                    "has_https", "has_at_symbol", "is_ip_address", "is_risky_tld", "brand_impersonation", 
                    "is_shortened", "has_redirect_params", "has_scam_keywords", "is_trusted_domain", 
                    "is_institutional_tld", "is_search_engine", "is_ai_platform", "is_streaming_platform", 
                    "is_coding_platform", "is_educational_platform", "is_social_platform", "has_malformed_chars", 
                    "has_script_payload", "has_homoglyph_spoof"
                ]:
                    is_pos = (val == 1)
                else:
                    if name == "url_length": is_pos = (val > 75)
                    elif name == "dot_count": is_pos = (val > 3)
                    elif name == "hyphen_count": is_pos = (val > 2)
                    elif name == "domain_entropy": is_pos = (val > 3.8)
                    elif name == "digit_ratio": is_pos = (val > 0.2)
                    elif name == "subdomain_count": is_pos = (val > 2)
                    elif name == "token_count": is_pos = (val > 5)
                    elif name == "keyword_density": is_pos = (val > 0.1)
                    elif name == "special_char_ratio": is_pos = (val > 0.2)
                    elif name == "query_entropy": is_pos = (val > 4.0)

                template = templates["positive"] if is_pos else templates["negative"]
                
                try:
                    msg = template.format(val=val)
                except Exception:
                    msg = template

                human_explanations.append({
                    "feature": name,
                    "impact_type": "RISK_FACTOR" if impact > 0 else "TRUST_FACTOR",
                    "impact_percent": f"{'+' if impact > 0 else ''}{impact*100:.1f}%",
                    "message": msg
                })

    # Filter explanations based on final classification outcome
    verdict_is_phish = final_prob > 0.50
    target_type = "RISK_FACTOR" if verdict_is_phish else "TRUST_FACTOR"
    
    # Sort and filter to maximum 5 explanation points (Phase 4 Requirement)
    sorted_exps = sorted(human_explanations, key=lambda x: abs(float(x["impact_percent"].replace('%','').replace('+',''))), reverse=True)
    filtered_exps = [exp for exp in sorted_exps if exp["impact_type"] == target_type]
    human_explanations_capped = filtered_exps[:5]

    # Combine signals with threat intelligence labels
    signals_combined = list(signals)
    for _, _, sig_msg in ti_triggers:
        signals_combined.append(sig_msg)

    # Analyst Report Summarization
    analyst_summary = generate_analyst_summary(feats_dict, final_prob > 0.50, final_prob, _risk_level(final_prob), signals_combined, ti_data)

    # Threat Timeline Generation
    threat_timeline = build_threat_timeline(feats_dict, raw_prob, adj_prob, final_prob, signals, ti_triggers)

    # SHAP Local Visualizations Generation
    # Create temporary total_impacts matching FEATURE_NAMES size
    visualizations = generate_local_plots(explainer, shap_values_obj, X, total_impacts, base_prob, final_prob)

    # Risk and Trust indicator lists
    risk_indicators = [exp["message"] for exp in human_explanations_capped if exp["impact_type"] == "RISK_FACTOR"]
    trust_indicators = [exp["message"] for exp in human_explanations_capped if exp["impact_type"] == "TRUST_FACTOR"]

    return {
        "url": sanitized_url,
        "is_phishing": final_prob > 0.50,
        "confidence_score": final_prob,
        "confidence": final_prob, # Backward compatibility
        "risk_level": _risk_level(final_prob),
        "triggered_signals": signals_combined,
        
        # Threat Intelligence Block (Phase 4 Requirement)
        "threat_intelligence": ti_data,
        
        # New Phase 3/4 XAI attributes
        "top_contributors": [{k: v for k, v in item.items() if k != "raw_impact"} for item in top_contributors[:8]],
        "feature_importance": [{k: v for k, v in item.items() if k != "raw_impact"} for item in top_contributors[:8]],
        "human_explanations": human_explanations_capped,
        "analyst_summary": analyst_summary,
        "threat_timeline": threat_timeline,
        "visualizations": visualizations,
        "features": feats_dict, # Backward compatibility
        "extracted_features": feats_dict, # Double compatibility
        
        # Analyst structured report fields
        "analyst_report": {
            "threat_summary": analyst_summary,
            "risk_indicators": risk_indicators,
            "trust_indicators": trust_indicators,
            "ml_feature_analysis": [{ "feature": item["feature"], "impact": item["impact"] } for item in top_contributors[:6]],
            "triggered_security_rules": signals_combined,
            "final_verdict": "PHISHING" if final_prob > 0.50 else "SAFE"
        }
    }
