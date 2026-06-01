import os
import pickle
import pandas as pd
import numpy as np
import shap
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

from feature_engineering import get_feature_list

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


def load_dataset_sample(csv_path: str, sample_size=300):
    """Loads and preprocesses a balanced sample from the dataset."""
    df = pd.read_csv(csv_path)
    url_col = next((c for c in df.columns if c.lower() == 'url'), df.columns[0])
    label_col = 'label' if 'label' in df.columns else df.columns[1]
    
    # Simple label detection/correction (same as train_model.py)
    if 'FILENAME' in df.columns:
        mw_rows = df[df['FILENAME'].astype(str).str.startswith('mw')]
        if len(mw_rows) > 0 and (mw_rows[label_col] == 0).mean() > 0.8:
            df[label_col] = 1 - df[label_col]
            
    # Sample balanced dataset
    safe_df = df[df[label_col] == 0]
    phish_df = df[df[label_col] == 1]
    
    half_size = sample_size // 2
    safe_sample = safe_df.sample(n=min(half_size, len(safe_df)), random_state=42)
    phish_sample = phish_df.sample(n=min(half_size, len(phish_df)), random_state=42)
    
    sample_df = pd.concat([safe_sample, phish_sample]).sample(frac=1, random_state=42).reset_index(drop=True)
    
    X_rows = []
    for idx, row in sample_df.iterrows():
        X_rows.append(get_feature_list(str(row[url_col])))
        
    X = pd.DataFrame(X_rows, columns=FEATURE_NAMES)
    y = sample_df[label_col].values
    urls = sample_df[url_col].values
    
    return X, y, urls


def run_model_audit():
    print("Starting Advanced XAI Model Audit...")
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    custom_csv = os.path.join(backend_dir, "dataset", "datasetphishing.csv")
    csv_path = custom_csv if os.path.exists(custom_csv) \
               else os.path.join(backend_dir, "dataset", "phishing.csv")
               
    model_path = os.path.join(backend_dir, "models", "phishing_model.pkl")
    exp_dir = os.path.join(backend_dir, "explanations")
    os.makedirs(exp_dir, exist_ok=True)
    
    if not os.path.exists(csv_path):
        print(f"Dataset not found at {csv_path}. Cannot perform audit.")
        return
        
    if not os.path.exists(model_path):
        print(f"Model not found at {model_path}. Run training first.")
        return

    # Load model
    with open(model_path, "rb") as f:
        model = pickle.load(f)

    # 1. Load balanced sample (300 items)
    print("Loading dataset sample...")
    X, y, urls = load_dataset_sample(csv_path, sample_size=300)

    # 2. Compute SHAP Values
    print("Computing SHAP values for global analysis...")
    explainer = shap.TreeExplainer(model)
    shap_values_obj = explainer(X)
    shap_values = shap_values_obj.values

    # 3. Generate SHAP Summary Plot
    print("Generating SHAP Summary Plot...")
    plt.figure(figsize=(10, 6))
    shap.summary_plot(shap_values, X, show=False)
    plt.title("SHAP Global Feature Impact Summary Plot", fontsize=12, fontweight='bold', pad=15)
    plt.tight_layout()
    plt.savefig(os.path.join(exp_dir, "global_summary_plot.png"), dpi=150)
    plt.close()
    
    # 4. Feature Correlation Matrix
    print("Generating Feature Correlation Analysis...")
    # Select non-constant features in sample to avoid division by zero
    non_constant_feats = [col for col in X.columns if X[col].std() > 0.01]
    # Filter to top 12 features by correlation with label for readability
    corrs = X[non_constant_feats].apply(lambda x: x.corr(pd.Series(y)))
    top_corr_feats = corrs.abs().nlargest(12).index.tolist()
    
    plt.figure(figsize=(10, 8))
    corr_matrix = X[top_corr_feats].corr()
    sns.heatmap(corr_matrix, annot=True, cmap="coolwarm", fmt=".2f", vmin=-1.0, vmax=1.0)
    plt.title("Feature Correlation Matrix (Top 12 Features)", fontsize=12, fontweight='bold', pad=15)
    plt.tight_layout()
    plt.savefig(os.path.join(exp_dir, "feature_correlation.png"), dpi=150)
    plt.close()

    # 5. Bias Detection Analysis
    print("Analyzing Model Biases...")
    preds = model.predict(X)
    probs = model.predict_proba(X)[:, 1]
    
    # Let's inspect protocol bias (HTTPS vs HTTP)
    https_mask = X["has_https"] == 1
    http_mask = X["has_https"] == 0
    
    https_prediction_rate = float(preds[https_mask].mean()) if https_mask.sum() > 0 else 0.0
    http_prediction_rate = float(preds[http_mask].mean()) if http_mask.sum() > 0 else 0.0
    
    # Risky TLD Bias
    risky_tld_mask = X["is_risky_tld"] == 1
    safe_tld_mask = X["is_risky_tld"] == 0
    risky_tld_pred_rate = float(preds[risky_tld_mask].mean()) if risky_tld_mask.sum() > 0 else 0.0
    safe_tld_pred_rate = float(preds[safe_tld_mask].mean()) if safe_tld_mask.sum() > 0 else 0.0

    # 6. Feature Dominance Detection
    print("Analyzing Feature Dominance...")
    mean_abs_shap = np.abs(shap_values).mean(axis=0)
    ranked_indices = np.argsort(mean_abs_shap)[::-1]
    top_features = [(FEATURE_NAMES[idx], float(mean_abs_shap[idx])) for idx in ranked_indices]
    
    # Feature dominance: what % of local predictions is dominated by the top feature?
    dominant_features = np.argmax(np.abs(shap_values), axis=1)
    unique, counts = np.unique(dominant_features, return_counts=True)
    dom_counts = sorted(zip(unique, counts), key=lambda x: x[1], reverse=True)
    
    dominance_stats = []
    for idx, count in dom_counts[:5]:
        pct = (count / len(X)) * 100
        dominance_stats.append({
            "feature": FEATURE_NAMES[idx],
            "count": int(count),
            "percentage": f"{pct:.1f}%"
        })

    # 7. False Positives & False Negatives Analysis
    print("Performing FP/FN Analysis...")
    false_positives = []
    false_negatives = []
    
    for i in range(len(y)):
        actual = y[i]
        pred = preds[i]
        prob = probs[i]
        url = urls[i]
        
        if actual == 0 and pred == 1:
            false_positives.append((url, float(prob)))
        elif actual == 1 and pred == 0:
            false_negatives.append((url, float(prob)))

    fp_count = len(false_positives)
    fn_count = len(false_negatives)
    
    # Identify features contributing most to FPs and FNs
    fp_contributors = {}
    if fp_count > 0:
        fp_indices = [i for i in range(len(y)) if y[i] == 0 and preds[i] == 1]
        mean_fp_shap = shap_values[fp_indices].mean(axis=0)
        top_fp_idx = np.argsort(mean_fp_shap)[::-1][:3]
        fp_contributors = {FEATURE_NAMES[idx]: f"+{mean_fp_shap[idx]*100:.1f}%" for idx in top_fp_idx if mean_fp_shap[idx] > 0.01}

    fn_contributors = {}
    if fn_count > 0:
        fn_indices = [i for i in range(len(y)) if y[i] == 1 and preds[i] == 0]
        mean_fn_shap = shap_values[fn_indices].mean(axis=0)
        top_fn_idx = np.argsort(mean_fn_shap)[:3]  # negative contributions (reducing risk)
        fn_contributors = {FEATURE_NAMES[idx]: f"{mean_fn_shap[idx]*100:.1f}%" for idx in top_fn_idx if mean_fn_shap[idx] < -0.01}

    # Assemble Audit Data
    audit_data = {
        "dataset_sample_size": len(y),
        "top_features": [{"feature": name, "importance": f"{imp*100:.2f}%"} for name, imp in top_features[:10]],
        "most_dangerous_features": [
            {"feature": "has_script_payload", "reason": "Triggers immediate max probability of 99% (Overrides Trust)"},
            {"feature": "has_malformed_chars", "reason": "Adds +60% risk score and overrides clean trust layers"},
            {"feature": "brand_impersonation", "reason": "Adds +30% risk score, highly correlated with targeted phishing"}
        ],
        "most_trusted_features": [
            {"feature": "is_trusted_domain", "reason": "Scales final probability down to <= 5% (Clean payload only)"},
            {"feature": "is_institutional_tld", "reason": "Scales final probability down to <= 8% (.edu/.gov TLDs)"},
            {"feature": "is_search_engine", "reason": "Reduces risk score by 75% for verified search indexers"}
        ],
        "bias_indicators": {
            "https_vs_http": {
                "https_phishing_prediction_rate": f"{https_prediction_rate*100:.1f}%",
                "http_phishing_prediction_rate": f"{http_prediction_rate*100:.1f}%",
                "description": "Indicates if the model has a shortcut rule predicting SAFE purely based on HTTPS connection presence."
            },
            "risky_tld_vs_safe": {
                "risky_tld_phishing_prediction_rate": f"{risky_tld_pred_rate*100:.1f}%",
                "safe_tld_phishing_prediction_rate": f"{safe_tld_pred_rate*100:.1f}%",
                "description": "Measures bias towards classifying domains with custom/risky TLDs as phishing."
            }
        },
        "feature_dominance": dominance_stats,
        "error_analysis": {
            "false_positives_count": fp_count,
            "false_negatives_count": fn_count,
            "false_positives_sample": [{"url": url, "confidence": f"{prob*100:.1f}%"} for url, prob in false_positives[:5]],
            "false_negatives_sample": [{"url": url, "confidence": f"{prob*100:.1f}%"} for url, prob in false_negatives[:5]],
            "top_false_positive_contributors": fp_contributors,
            "top_false_negative_contributors": fn_contributors
        }
    }

    # Save JSON Report
    import json
    with open(os.path.join(exp_dir, "model_audit_report.json"), "w") as f:
        json.dump(audit_data, f, indent=2)
        
    # Save Markdown Report
    md_content = f"""# XPhishGuard AI — Model Audit Report

Generated automatically using SHAP explainability matrices and dataset validations.

## 1. Global Feature Importance (SHAP Average Impact)
The following features exhibit the largest mean absolute SHAP contribution across the balanced dataset:

| Rank | Feature Name | Mean Absolute SHAP Impact |
|------|--------------|---------------------------|
"""
    for idx, item in enumerate(audit_data["top_features"], 1):
        md_content += f"| {idx} | `{item['feature']}` | {item['importance']} |\n"
        
    md_content += """
## 2. Most Dangerous Features (High Threat Indicators)
Features that represent high-risk attack actions. They trigger immediate overrides or significant model score increases:
"""
    for item in audit_data["most_dangerous_features"]:
        md_content += f"- **`{item['feature']}`**: {item['reason']}\n"
        
    md_content += """
## 3. Most Trusted Features (Trust Anchors)
Features representing established trust which reduce the calculated risk score:
"""
    for item in audit_data["most_trusted_features"]:
        md_content += f"- **`{item['feature']}`**: {item['reason']}\n"

    md_content += f"""
## 4. Bias Indicators
To verify that the machine learning model does not rely on shortcuts, we analyze classification rates across key feature segments:

* **Protocol Bias**: Phishing classification rate is **{audit_data['bias_indicators']['https_vs_http']['https_phishing_prediction_rate']}** for HTTPS URLs vs. **{audit_data['bias_indicators']['https_vs_http']['http_phishing_prediction_rate']}** for HTTP URLs.
* **TLD Bias**: Phishing classification rate is **{audit_data['bias_indicators']['risky_tld_vs_safe']['risky_tld_phishing_prediction_rate']}** for risky TLDs (.xyz, .club, etc.) vs. **{audit_data['bias_indicators']['risky_tld_vs_safe']['safe_tld_phishing_prediction_rate']}** for standard TLDs.

## 5. Feature Dominance (Local Decision Driver)
Features that drive the largest local prediction shifts most frequently:
"""
    for item in audit_data["feature_dominance"]:
        md_content += f"- **`{item['feature']}`** was the single most dominant factor in **{item['count']}** predictions ({item['percentage']})\n"

    md_content += f"""
## 6. Error Analysis
Based on evaluating {len(y)} balanced URLs:
- **False Positives (Safe URL flagged as Phishing)**: {fp_count} occurrences
- **False Negatives (Phishing URL flagged as Safe)**: {fn_count} occurrences

### Top Features Driving False Positives:
"""
    for feat, impact in fp_contributors.items():
        md_content += f"- `{feat}`: contributed an average of {impact} to false flags\n"
    if not fp_contributors:
        md_content += "- None detected in this sample.\n"

    md_content += """
### Top Features Driving False Negatives:
"""
    for feat, impact in fn_contributors.items():
        md_content += f"- `{feat}`: reduced score by an average of {impact} leading to leakages\n"
    if not fn_contributors:
        md_content += "- None detected in this sample.\n"

    with open(os.path.join(exp_dir, "model_audit_report.md"), "w") as f:
        f.write(md_content)
        
    print("Saved model_audit_report.json and model_audit_report.md in backend/explanations/")
    print("Saved plots in backend/explanations/")


if __name__ == "__main__":
    run_model_audit()
