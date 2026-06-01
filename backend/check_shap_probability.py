import pickle
import os
import pandas as pd
import numpy as np
import shap

backend_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(backend_dir, "models", "phishing_model.pkl")

with open(model_path, "rb") as f:
    model = pickle.load(f)

# Generate dummy feature vector (29 features)
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

X = pd.DataFrame(dummy_data, columns=FEATURE_NAMES)

print("Creating SHAP probability explainer...")
try:
    # Try using probability model output (requires background dataset or path dependent tree explainer)
    explainer = shap.TreeExplainer(model, model_output='probability')
    shap_values = explainer(X)
    print("Success with model_output='probability'!")
    print("Base value:", explainer.expected_value)
    print("Sum of SHAP values:", shap_values.values.sum(axis=1))
except Exception as e:
    print("Failed with model_output='probability':", e)

print("\nTrying with background dataset...")
try:
    # Use a small background dataset (e.g. 10 rows of zeros)
    bg_data = np.zeros((10, 29))
    explainer = shap.TreeExplainer(model, data=bg_data, model_output='probability')
    shap_values = explainer(X)
    print("Success with background dataset and model_output='probability'!")
    print("Base value:", explainer.expected_value)
    print("Sum of SHAP values:", shap_values.values.sum(axis=1))
except Exception as e:
    print("Failed with background dataset:", e)
