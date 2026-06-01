import pickle
import os
import pandas as pd
import numpy as np
import shap

backend_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(backend_dir, "models", "phishing_model.pkl")

with open(model_path, "rb") as f:
    model = pickle.load(f)

print("Model loaded successfully:", type(model))

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
# Set some features to 1
dummy_data[0, 6] = 1 # is_risky_tld
dummy_data[0, 7] = 1 # brand_impersonation

X = pd.DataFrame(dummy_data, columns=FEATURE_NAMES)

print("Creating SHAP explainer...")
explainer = shap.TreeExplainer(model)
print("Computing SHAP values...")
shap_values = explainer(X)

print("SHAP base value:", explainer.expected_value)
print("SHAP values shape:", shap_values.values.shape)
print("Success!")
