# XPhishGuard AI — Model Audit Report

Generated automatically using SHAP explainability matrices and dataset validations.

## 1. Global Feature Importance (SHAP Average Impact)
The following features exhibit the largest mean absolute SHAP contribution across the balanced dataset:

| Rank | Feature Name | Mean Absolute SHAP Impact |
|------|--------------|---------------------------|
| 1 | `url_length` | 209.22% |
| 2 | `subdomain_count` | 58.75% |
| 3 | `special_char_ratio` | 50.60% |
| 4 | `domain_entropy` | 50.25% |
| 5 | `is_risky_tld` | 33.86% |
| 6 | `dot_count` | 30.39% |
| 7 | `token_count` | 25.17% |
| 8 | `is_trusted_domain` | 16.43% |
| 9 | `is_institutional_tld` | 16.12% |
| 10 | `digit_ratio` | 13.00% |

## 2. Most Dangerous Features (High Threat Indicators)
Features that represent high-risk attack actions. They trigger immediate overrides or significant model score increases:
- **`has_script_payload`**: Triggers immediate max probability of 99% (Overrides Trust)
- **`has_malformed_chars`**: Adds +60% risk score and overrides clean trust layers
- **`brand_impersonation`**: Adds +30% risk score, highly correlated with targeted phishing

## 3. Most Trusted Features (Trust Anchors)
Features representing established trust which reduce the calculated risk score:
- **`is_trusted_domain`**: Scales final probability down to <= 5% (Clean payload only)
- **`is_institutional_tld`**: Scales final probability down to <= 8% (.edu/.gov TLDs)
- **`is_search_engine`**: Reduces risk score by 75% for verified search indexers

## 4. Bias Indicators
To verify that the machine learning model does not rely on shortcuts, we analyze classification rates across key feature segments:

* **Protocol Bias**: Phishing classification rate is **32.9%** for HTTPS URLs vs. **63.1%** for HTTP URLs.
* **TLD Bias**: Phishing classification rate is **100.0%** for risky TLDs (.xyz, .club, etc.) vs. **37.4%** for standard TLDs.

## 5. Feature Dominance (Local Decision Driver)
Features that drive the largest local prediction shifts most frequently:
- **`url_length`** was the single most dominant factor in **195** predictions (65.0%)
- **`subdomain_count`** was the single most dominant factor in **26** predictions (8.7%)
- **`domain_entropy`** was the single most dominant factor in **25** predictions (8.3%)
- **`special_char_ratio`** was the single most dominant factor in **21** predictions (7.0%)
- **`is_risky_tld`** was the single most dominant factor in **17** predictions (5.7%)

## 6. Error Analysis
Based on evaluating 300 balanced URLs:
- **False Positives (Safe URL flagged as Phishing)**: 6 occurrences
- **False Negatives (Phishing URL flagged as Safe)**: 32 occurrences

### Top Features Driving False Positives:
- `digit_ratio`: contributed an average of +67.6% to false flags
- `subdomain_count`: contributed an average of +48.0% to false flags
- `is_risky_tld`: contributed an average of +37.3% to false flags

### Top Features Driving False Negatives:
- `url_length`: reduced score by an average of -178.1% leading to leakages
- `subdomain_count`: reduced score by an average of -36.5% leading to leakages
- `domain_entropy`: reduced score by an average of -20.7% leading to leakages
