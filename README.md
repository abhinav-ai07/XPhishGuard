**XPhishGuard AI** is a multi-tier cybersecurity intelligence and phishing detection ecosystem designed for enterprise Security Operations Centers (SOC) and real-time end-user defense. It combines **29-feature structural & semantic URL engineering**, **machine learning classification**, **explainable AI (SHAP)**, and **real-time threat feeds** into a single cohesive platform.

The ecosystem is architected around **three core pillars** communicating through a centralized API gateway:

1. **`backend/`**: High-throughput Python Flask REST API, 29-feature extractor, Random Forest classification engine, live Threat Intel integration, SHAP explainability, and risk scorecards.
2. **`frontend/`**: Cyber SOC Analyst Dashboard built with React 19, Vite, and Tailwind CSS.
3. **`browser-extension/`**: Manifest V3 Chromium Extension for real-time URL inspection, automated tab evaluation, and glassmorphism alerts.

---

## 1. System Architecture & Data Flow

```
                      +──────────────────────────────────────────+
                      |               CLIENT LAYER               |
                      |                                          |
                      |  +──────────────────+  +───────────────+ |
                      |  | React 19 Web App |  | MV3 Extension | |
                      |  |   (localhost)    |  |  (Chrome/Edge)| |
                      |  +─────────┬────────+  +───────┬───────+ |
                      +────────────┼───────────────────┼─────────+
                                   |                   |
                                   v  [HTTP JSON POST] v
+───────────────────────────────────────────────────────────────────────────+
|                           BACKEND API GATEWAY                             |
|                        Flask API (Port 5000)                              |
|                                                                           |
|   +-------------------------------------------------------------------+   |
|   |                  29-Feature Extraction Pipeline                   |   |
|   |  - Structural / Lexical Features (Length, Dots, Hyphens, TLD)     |   |
|   |  - Semantic Platform Features (AI, Streaming, Dev, Social)        |   |
|   |  - Obfuscation & Payload Checks (Homoglyphs, Scripts, Char Ratio) |   |
|   +───────────────────────────────────┬───────────────────────────────+   |
|                                       |                                   |
|               +───────────────────────┴───────────────────────+           |
|               v                                               v           |
|   +──────────────────────+                        +───────────────────+   |
|   |  ML Inference Engine |                        | Threat Intel Feeds|   |
|   | (Random Forest Model)|                        | - VirusTotal v3   |   |
|   | - Confidence Score   |                        | - PhishTank       |   |
|   | - Probability Output |                        | - OpenPhish       |   |
|   +───────────┬──────────+                        | - URLHaus         |   |
|               |                                   +─────────┬─────────+   |
|               +───────────────────────┬─────────────────────+             |
|                                       v                                   |
|   +───────────────────────────────────────────────────────────────────+   |
|   |                   Threat Synthesis & Explainability               |   |
|   |  - SHAP Force & Waterfall Generation (Local Contributions)        |   |
|   |  - Brand Spoofing Detection (Levenshtein & Canonical Mapping)     |   |
|   |  - Attack Classification (Credential Theft, Drive-By, etc.)      |   |
|   |  - Weighted Risk Scorecard (0 - 100%)                             |   |
|   |  - Plain-English Natural Language Explanations                    |   |
|   +───────────────────────────────────┬───────────────────────────────+   |
|                                       |                                   |
+───────────────────────────────────────┼───────────────────────────────────+
                                        |
                                        v [Unified JSON Response]
                      +──────────────────────────────────────────+
                      |         Real-Time Threat Dossier         |
                      |  - Verdict: SAFE / SUSPICIOUS / DANGEROUS|
                      |  - Interactive SHAP Impact Graphs        |
                      |  - Actionable Remediation Guidance       |
                      +──────────────────────────────────────────+
```

---

## 2. Directory Structure

```
XPhishGuard/
├── backend/                       # Pillar 1: Python Flask API & ML Inference Engine
│   ├── dataset/                   # Dataset directory (datasetphishing.csv - gitignored)
│   ├── explanations/              # Generated XAI plots & model audit reports
│   ├── models/                    # Serialized trained model (phishing_model.pkl)
│   ├── services/                  # Threat intelligence integrations
│   │   ├── openphish.py           # OpenPhish live feed parser
│   │   ├── phishtank.py           # PhishTank verification API
│   │   ├── urlhaus.py             # URLHaus malware/phishing intelligence
│   │   └── virustotal.py          # VirusTotal v3 detections lookup
│   ├── tests/                     # Standardized Python test suite
│   │   ├── __init__.py
│   │   ├── test_bias.py           # Domain bias and edge-case validation
│   │   ├── test_payloads.py       # Obfuscation, homoglyphs & payload tests
│   │   ├── test_predictions.py    # Known safe and phishing URL verification
│   │   ├── test_predict_explain.py# Explainability pipeline integration test
│   │   └── test_threat_intel.py   # Multi-provider threat intelligence test
│   ├── attack_classifier.py       # Phishing attack type taxonomy classifier
│   ├── brand_detector.py          # Brand impersonation & typosquatting detector
│   ├── feature_engineering.py     # 29-feature structural & semantic URL parser
│   ├── main.py                    # Flask API Gateway (Endpoints: /api/predict, /api/health)
│   ├── predict.py                 # Core inference, threat aggregation & SHAP pipeline
│   ├── recommendation_engine.py   # Security recommendations & playbook generator
│   ├── report_generator.py        # Executive threat dossier & summary builder
│   ├── requirements.txt           # Python dependencies
│   ├── risk_engine.py             # Multi-vector weighted risk score calculator
│   ├── threat_intel.py            # Threat intelligence coordinator
│   ├── train_model.py             # Model training & cross-validation script
│   └── xai_advanced.py            # Global model audit & SHAP fairness engine
├── frontend/                      # Pillar 2: React 19 + Vite SOC Dashboard
│   ├── public/                    # Static public assets
│   ├── src/
│   │   ├── assets/                # Icons and branding graphics
│   │   ├── components/            # SOC UI components (ResultCard, ThreatMeter, XAI charts)
│   │   ├── services/              # API bindings connected to http://localhost:5000/api
│   │   ├── App.jsx                # Main SOC view (Scanner + Model Auditing tabs)
│   │   ├── index.css              # Tailwind base stylesheet & animations
│   │   └── main.jsx               # React DOM entry point
│   ├── package.json               # Node.js dependencies and build scripts
│   ├── tailwind.config.js         # Cyberpunk-inspired SOC color theme
│   ├── vite.config.js             # Vite configuration
│   └── README.md                  # Frontend development documentation
├── browser-extension/             # Pillar 3: Manifest V3 Browser Extension
│   ├── icons/                     # Extension icons (16x16, 48x48, 128x128)
│   ├── background.js              # Service worker (Context menus, desktop notifications)
│   ├── content.js                 # Content script for active page bridge
│   ├── manifest.json              # Extension manifest V3 metadata & permissions
│   ├── popup.html                 # Glassmorphism extension popup layout
│   ├── popup.css                  # Modern dark-mode styling
│   ├── popup.js                   # Popup controller & threat score visualizer
│   ├── service.js                 # Unified API client communicating with Flask backend
│   ├── utils.js                   # URL formatting, history storage & coloring utilities
│   └── README.md                  # Browser extension installation & setup guide
├── .env.example                   # Threat Intelligence API keys template
├── .gitignore                     # Comprehensive Git exclusion rules
└── README.md                      # Master repository documentation
```

---

## 3. Quickstart Guide

### Prerequisites
- **Python**: 3.10 or higher
- **Node.js**: 18.0 or higher
- **Chromium Browser**: Google Chrome, Microsoft Edge, Brave, or Opera

---

### Step 1: Start the Backend (Flask API)

1. Open your terminal in the repository root:
   ```bash
   # Create a virtual environment (if not already created)
   python -m venv .venv

   # Activate virtual environment
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```

3. (Optional) Set up Threat Intelligence API Keys:
   ```bash
   cp .env.example .env
   ```
   Add your `VT_API_KEY` (VirusTotal) or `PHISHTANK_API_KEY` into `.env`. The system works seamlessly with or without keys (uses offline heuristics if offline).

4. Launch the API Gateway:
   ```bash
   python backend/main.py
   ```
   The backend will start on **`http://localhost:5000`**. You can verify it at `http://localhost:5000/api/health`.

---

### Step 2: Run the Frontend (React SOC Dashboard)

1. In a new terminal window, navigate to the `frontend` directory:
   ```bash
   cd frontend
   ```

2. Install Node packages:
   ```bash
   npm install
   ```

3. Start the Vite development server:
   ```bash
   npm run dev
   ```
   Open **`http://localhost:5173`** in your browser to access the SOC Analyst Dashboard.

---

### Step 3: Install the Browser Extension

1. Open Google Chrome or Microsoft Edge.
2. Navigate to:
   - Chrome: `chrome://extensions/`
   - Edge: `edge://extensions/`
3. Toggle on **Developer mode** in the top-right corner.
4. Click **Load unpacked** in the top-left toolbar.
5. Select the `browser-extension` folder inside the `XPhishGuard` directory.
6. Pin the **XPhishGuard AI** extension to your browser toolbar.
7. Any website you visit can now be inspected instantly by clicking the extension icon or right-clicking links!

---

## 4. API Endpoints Reference

Base URL: `http://localhost:5000`

### `GET /api/health`
Checks backend API gateway status.
```json
{
  "success": true,
  "message": "XPhishGuard API Gateway is healthy and running."
}
```

### `POST /api/predict`
Scans a target URL through the 29-feature pipeline, Random Forest classifier, threat intel feeds, and SHAP explainability engine.

**Request:**
```json
{
  "url": "http://paypal-security-update.xyz/login"
}
```

**Response (Summary):**
```json
{
  "success": true,
  "url": "http://paypal-security-update.xyz/login",
  "is_phishing": true,
  "confidence_score": 0.94,
  "risk_level": "DANGEROUS",
  "risk_scorecard": {
    "overall_risk": 94,
    "brand_impersonation": 95,
    "url_structure": 88,
    "domain_reputation": 90
  },
  "brand_detection": {
    "is_impersonating": true,
    "likely_target_brand": "PayPal"
  },
  "attack_classification": {
    "primary_attack_type": "Credential Harvesting Phishing"
  },
  "top_contributors": [
    { "feature": "brand_impersonation", "impact": "+0.42" },
    { "feature": "is_risky_tld", "impact": "+0.31" },
    { "feature": "has_https", "impact": "+0.18" }
  ],
  "human_explanations": [
    {
      "message": "Domain attempts to mimic PayPal using an unauthorized domain pattern.",
      "impact_type": "high_risk",
      "impact_percent": "42%"
    }
  ],
  "recommendations": [
    "Do not input usernames, passwords, or payment credentials.",
    "Block domain on enterprise perimeter firewalls."
  ]
}
```

### `GET /api/audit`
Retrieves the global SHAP model audit report, fairness benchmarks, and base64 encoded correlation heatmaps.

---

## 5. 29 Engineered Features Overview

| Feature Name | Category | Cybersecurity Risk Significance |
|:---|:---|:---|
| `url_length` | Lexical | Long URLs hide malicious hostnames off-screen |
| `dot_count` | Lexical | Excessive dots denote nested deceptive subdomains |
| `hyphen_count` | Lexical | Attackers use hyphens to concatenate brand keywords |
| `has_https` | Protocol | Analyzes protocol integrity |
| `has_at_symbol` | Obfuscation | `@` in URL causes browsers to ignore the preceding prefix |
| `is_ip_address` | Structural | Raw IP usage bypasses DNS reputation filters |
| `is_risky_tld` | TLD | High-risk abuse TLDs (`.xyz`, `.top`, `.tk`, `.ru`, `.cc`) |
| `brand_impersonation` | Semantic | Detects typosquatting and brand keyword mimicry |
| `domain_entropy` | Algorithmic | Measures algorithmic randomness (DGA domains) |
| `digit_ratio` | Structural | Excessive numbers indicate randomized phishing campaigns |
| `subdomain_count` | Structural | Multi-tier subdomains spoofing authentic organizations |
| `token_count` | Lexical | High tokenization indicates complex path tampering |
| `keyword_density` | Semantic | Concentration of urgency words (`login`, `secure`, `verify`) |
| `is_shortened` | Redirection | Shorteners (`bit.ly`, `t.co`) mask actual destinations |
| `has_redirect_params` | Redirection | Open redirects (`?next=`, `?redirect=`, `?url=`) |
| `has_scam_keywords` | Content | Blacklisted lure keywords and scam terminology |
| `is_trusted_domain` | Reputation | Known safe whitelist baseline to prevent false positives |
| `is_institutional_tld` | Trust | `.gov`, `.edu`, `.mil` high-reputation domains |
| `is_search_engine` | Platform | Legitimate search engine domains |
| `is_ai_platform` | Platform | Modern generative AI domains (`chatgpt.com`, `claude.ai`) |
| `is_streaming_platform`| Platform | Legitimate streaming services (`youtube.com`, `netflix.com`) |
| `is_coding_platform` | Platform | Developer platforms (`github.com`, `gitlab.com`, `stackoverflow.com`) |
| `is_educational_platform`| Platform | Learning platforms (`coursera.org`, `edx.org`, `udemy.com`) |
| `is_social_platform` | Platform | Social networks (`twitter.com`, `linkedin.com`, `facebook.com`) |
| `has_malformed_chars` | Obfuscation | Illegal characters (`!}`, `{`, `^`, `\`) in URL |
| `special_char_ratio` | Obfuscation | Elevated density of non-alphanumeric characters |
| `query_entropy` | Algorithmic | Randomness in GET parameter strings |
| `has_script_payload` | Payload | XSS / injection markers (`<script>`, `javascript:`, `%3Cscript`) |
| `has_homoglyph_spoof` | Obfuscation | Cyrillic / Unicode lookalike character substitution |

---

## 6. Running the Test Suite

All tests are organized inside `backend/tests/`:

```bash
# Run Obfuscation and Payload tests
python backend/tests/test_payloads.py

# Run Safe vs Phishing URL validation
python backend/tests/test_predictions.py

# Run Bias & False Positive validation
python backend/tests/test_bias.py

# Run Threat Intelligence integration tests
python backend/tests/test_threat_intel.py

# Run Explainability & SHAP tests
python backend/tests/test_predict_explain.py
```

---

## 7. Adding to GitHub

To push this repository to GitHub:

```bash
# Initialize git (if not already initialized)
git init

# Stage all organized files (respects .gitignore)
git add .

# Commit changes
git commit -m "feat: organize project into 3-pillar architecture (backend, frontend, browser-extension)"

# Set your branch and remote
git branch -M main
git remote add origin https://github.com/<your-username>/XPhishGuard.git

# Push to GitHub
git push -u origin main
```

---

## 8. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
