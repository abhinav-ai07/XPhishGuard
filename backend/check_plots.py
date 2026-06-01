import pickle
import os
import pandas as pd
import numpy as np
import shap
import matplotlib
matplotlib.use('Agg') # Use non-interactive backend
import matplotlib.pyplot as plt

backend_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(backend_dir, "models", "phishing_model.pkl")

with open(model_path, "rb") as f:
    model = pickle.load(f)

# Generate dummy feature vector
FEATURE_NAMES = [
    "url_length", "dot_count", "hyphen_count", "has_https",
    "has_at_symbol", "is_ip_address", "is_risky_tld", "brand_impersonation",
    "domain_entropy", "digit_ratio", "subdomain_count", "token_count",
    "keyword_density", "is_shortened", "has_redirect_params",
    "has_scam_keywords", "is_trusted_domain", "is_institutional_tld",
    "is_search_engine", "is_ai_platform", "is_streaming_platform",
    "is_coding_platform", "is_educational_platform", "is_social_platform",
    "has_malformed_chars", "special_char_ratio", "query_entropy",
    "has_script_payload", "has_homoglyph_spoof"
]

dummy_data = np.zeros((1, 29))
dummy_data[0, 6] = 1 # is_risky_tld
dummy_data[0, 7] = 1 # brand_impersonation
dummy_data[0, 0] = 50 # url_length

X = pd.DataFrame(dummy_data, columns=FEATURE_NAMES)
explainer = shap.TreeExplainer(model)
shap_values = explainer(X)

# Create explanations directory
exp_dir = os.path.join(backend_dir, "explanations")
os.makedirs(exp_dir, exist_ok=True)

# 1. Feature Importance Bar Chart (Local)
plt.figure(figsize=(10, 6))
# Sort features by absolute contribution
contribs = shap_values.values[0]
sorted_idx = np.argsort(np.abs(contribs))[-10:] # Top 10
plt.barh(np.array(FEATURE_NAMES)[sorted_idx], contribs[sorted_idx], color=['red' if x > 0 else 'blue' for x in contribs[sorted_idx]])
plt.title("Top Local Feature Contributions (Log-Odds)")
plt.xlabel("SHAP Value")
plt.tight_layout()
plt.savefig(os.path.join(exp_dir, "local_importance.png"))
plt.close()
print("Saved local_importance.png")

# 2. SHAP Waterfall Plot
plt.figure(figsize=(10, 6))
try:
    # In newer versions of SHAP, shap.plots.waterfall takes an Explanation object
    shap.plots.waterfall(shap_values[0], max_display=10, show=False)
    plt.tight_layout()
    plt.savefig(os.path.join(exp_dir, "waterfall.png"))
    plt.close()
    print("Saved waterfall.png")
except Exception as e:
    print("Failed to save waterfall.png via shap.plots:", e)

# 3. SHAP Force Plot
plt.figure(figsize=(12, 4))
try:
    # For local force plot with matplotlib=True
    shap.plots.force(explainer.expected_value, shap_values.values[0], X.iloc[0], matplotlib=True, show=False)
    plt.tight_layout()
    plt.savefig(os.path.join(exp_dir, "force.png"))
    plt.close()
    print("Saved force.png")
except Exception as e:
    print("Failed to save force.png via shap.plots:", e)
