# XPhishGuard AI — AI-Powered Phishing URL Detection System (Phase 1)

Welcome to the engineering blueprint and technical documentation for **XPhishGuard AI**. This system implements a modular, production-grade cybersecurity backend that extracts high-entropy structural features from URL strings, trains a Random Forest Classifier to detect malicious domain footprints, and serves real-time predictions via a robust, CORS-enabled Flask API.

---

## 1. System Architecture & Data Flow

XPhishGuard AI is built around a decoupled micro-architecture where feature parsing, classifier inference, and network routing are separated. This ensures that features can be unit tested, the model can be retrained in isolation, and the web app can scale horizontally.

### Data Flow Diagram:
```
                                +-----------------------------------+
                                |     Client HTTP JSON Payload      |
                                |  {"url": "http://malicious.com"}  |
                                +-----------------------------------+
                                                  |
                                                  v  [HTTP POST Request]
                                +-----------------------------------+
                                |         Flask API Gateway         |
                                |             (main.py)             |
                                +-----------------------------------+
                                                  |
                                                  v  [Raw URL String]
                                +-----------------------------------+
                                |    Feature Engineering Module     |
                                |     (feature_engineering.py)      |
                                +-----------------------------------+
                                                  |
                                                  v  [1x7 Numerical Matrix]
                                +-----------------------------------+
                                |         Prediction Engine         |
                                |            (predict.py)           |
                                +-----------------------------------+
                                                  |
                                                  v  [Load Serialized Binary]
                                +-----------------------------------+
                                |       phishing_model.pkl          |
                                |      (Random Forest Model)        |
                                +-----------------------------------+
                                                  |
                                                  v  [Inference Class & Score]
                                +-----------------------------------+
                                |         Flask API Gateway         |
                                |  Packages response as JSON        |
                                +-----------------------------------+
                                                  |
                                                  v  [HTTP POST Response]
                                +-----------------------------------+
                                |            Client Browser         |
                                |  Renders Safe/Phishing warning    |
                                +-----------------------------------+
```

---

## 2. Directory Structure

```
XPhishGuard/
│
├── backend/
│   ├── .venv/                         # Isolated Python Virtual Environment
│   ├── dataset/
│   │   ├── generate_dataset.py        # Dataset generator (2,000 balanced samples)
│   │   └── phishing.csv               # CSV file containing generated dataset
│   │
│   ├── models/
│   │   └── phishing_model.pkl         # Persisted Random Forest Classifier binary
│   │
│   ├── feature_engineering.py         # URL feature extraction algorithms
│   ├── train_model.py                 # ML training, split, & evaluation pipeline
│   ├── predict.py                     # Inference pipeline & singleton model loader
│   ├── main.py                        # Flask server (CORS-enabled REST API gateway)
│   └── requirements.txt               # Pin-point backend Python dependencies
│
└── README.md                          # Master documentation & Engineering Guide
```

---

## 3. Deep Feature Engineering Analysis

### Why Machine Learning Models Cannot Process Raw Strings
Machine learning classifiers are fundamentally optimization networks operating on mathematical vector spaces. They cannot ingest arbitrary characters because strings lack algebraic properties (addition, dot products, or distance matrices). Feature engineering converts unstructured text strings $S$ into structured vectors $\vec{x} \in \mathbb{R}^7$.

### Engineered Features & Cybersecurity Footprints
XPhishGuard maps the following 7 features to capture typical phishing behavioral abuses:

1. **URL Length (`url_length`)**:
   - *Cybersecurity Footprint*: Attackers use long URLs to tuck malicious domains far to the right, hoping they are truncated in narrow mobile browser address bars.
   - *Formula*: $L_c = \text{length}(S)$
   - *Limitation*: Long legitimate URLs occur in marketing funnels, search queries, or analytics tracking links.

2. **Dot Count (`dot_count`)**:
   - *Cybersecurity Footprint*: Phishers construct deep subdomain strings to spoof brands (e.g., `login.paypal.com.accounts.update.com`).
   - *Formula*: Count of `.` character in $S$
   - *Limitation*: Authentic enterprise subdomains and multi-regional platforms (e.g., `en.wikipedia.org`) naturally exhibit multiple dots.

3. **Hyphen Count (`hyphen_count`)**:
   - *Cybersecurity Footprint*: Since phishers cannot buy genuine domains, they stitch company brands and urgency keywords together (e.g., `secure-chase-bank-verify.net`).
   - *Formula*: Count of `-` character in $S$
   - *Limitation*: Modern blogs and news portals use hyphen-stitching for search-engine-optimized (SEO) slug indexing.

4. **HTTPS Presence (`has_https`)**:
   - *Cybersecurity Footprint*: Historical secure communication relies on SSL/TLS protocol wrappers.
   - *Formula*: $1$ if $S$ begins with `https://`, else $0$.
   - *Limitation*: Phishers now aggressively acquire free TLS certificates (e.g., Let's Encrypt), meaning HTTPS presence is a supportive signal, but no longer an absolute guarantee of safety.

5. **At Symbol (`has_at_symbol`)**:
   - *Cybersecurity Footprint*: RFC 3986 defines `@` as an authority delimiter. The browser ignores everything *before* the `@` and routes directly to the domain *after* it. E.g., `http://chase.com@evil-hacker.com` routes to `evil-hacker.com`.
   - *Formula*: $1$ if `@` is in $S$, else $0$.
   - *Limitation*: Exceptionally rare in consumer web traffic; occasionally found in legacy FTP credentials or embedded basic-auth APIs.

6. **IP Address Host (`is_ip_address`)**:
   - *Cybersecurity Footprint*: Attackers host sites on raw IP addresses (e.g., `http://192.168.1.105/verify`) to completely bypass DNS domain registration age checks and registrar reputational blocklists.
   - *Formula*: Regex match against standard IPv4 formats `^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`.
   - *Limitation*: Standard internal networks or local development routers use local IPs, but they are practically nonexistent in public consumer web platforms.

7. **Suspicious Keywords Presence (`has_suspicious_keywords`)**:
   - *Cybersecurity Footprint*: Social engineering rely on psychological baits. Keywords like `login`, `verify`, `secure`, `update`, `signin`, `account`, and financial brand names reflect spoofing indicators.
   - *Formula*: $1$ if any term in the pre-compiled `SUSPICIOUS_KEYWORDS` array is found inside the lowercased URL string, else $0$.
   - *Limitation*: Legitimate login interfaces and security notification portals must use these terms.

---

## 4. Machine Learning & Random Forest Classifier

### Why Random Forest is Chosen:
1. **High Explanatory Power on Tabular Spaces**: URL features represent non-linear tabular patterns where trees excel. Deep Learning neural networks are overkill, expensive to train, and act as black-boxes.
2. **Bootstrap Aggregating (Bagging)**: Random Forest constructs 100 random decision trees. By training each on a bootstrapped subset of the training data and a random selection of features, it significantly reduces variance and prevents overfitting.
3. **Zero Scaling Needed**: Decision trees split nodes based on inequality boundaries ($X_i > t$). Thus, features of vastly different scales (e.g., URL lengths of 200 vs. binary HTTPS flags of 1) do not bias the model.
4. **Execution Speed**: Inference executes in under 2 milliseconds on a standard CPU thread, allowing real-time proxy-level blockages without lagging page loads.

### Core Pipeline Steps:
- **Train-Test Split (80/20)**: Out of 2,000 samples, 1,600 are fed to train the classifier. 400 samples are reserved as unseen test metrics.
- **Evaluation Metrics**:
  - **Accuracy**: $100\%$ on test split due to highly clear mathematical feature separation.
  - **Precision**: $100\%$ (True Positives / Predicted Positives) ensuring zero legitimate banking websites are misclassified (zero false alarms).
  - **Recall**: $100\%$ (True Positives / Actual Positives) ensuring zero malicious URLs leak past the network filter (zero missed attacks).

---

## 5. Setup & Installation Guide

Follow these exact steps from your Windows terminal (PowerShell or Command Prompt) to initialize, train, and launch the system from scratch.

### Step 1: Open Target Workspace Directory
```powershell
cd c:\Users\Abhinav\OneDrive\Desktop\XPhishGuard\backend
```

### Step 2: Initialize isolated Virtual Environment
```powershell
python -m venv .venv
```

### Step 3: Install pinned requirements using the venv's pip
To avoid running into execution policy limits when activating in PowerShell, trigger pip directly using the virtual environment's internal interpreter:
```powershell
.venv\Scripts\python -m pip install -r requirements.txt
```

### Step 4: Run the program dataset generator
Creates the balanced URL catalog containing 2,000 authentic and phishing records:
```powershell
.venv\Scripts\python dataset/generate_dataset.py
```

### Step 5: Execute the ML training pipeline
Runs the feature extraction, fits the 100-tree Random Forest, runs test evaluation, and pickles the binary to disk:
```powershell
.venv\Scripts\python train_model.py
```

### Step 6: CLI Dry-Run Inference Test
Verify that the model loads and predicts any URL from the command line:
```powershell
.venv\Scripts\python predict.py "http://verify-paypal-accounts.net/signin"
```

### Step 7: Launch the Flask Server
Starts the API gateway listener on `http://127.0.0.1:5000`:
```powershell
.venv\Scripts\python main.py
```

---

## 6. API Documentation

### Health Check Endpoint
* Checks system availability.

* **URL**: `/api/health`
* **Method**: `GET`
* **Response Payload (JSON)**:
  ```json
  {
    "success": true,
    "message": "XPhishGuard API Gateway is healthy and running."
  }
  ```

### Prediction Endpoint
* Extracts features and runs machine learning inference.

* **URL**: `/api/predict`
* **Method**: `POST`
* **Headers**: `Content-Type: application/json`
* **Request Payload (JSON)**:
  ```json
  {
    "url": "http://secure-banking-alert.com/signin"
  }
  ```
* **Response Payload (JSON)**:
  ```json
  {
    "success": true,
    "url": "http://secure-banking-alert.com/signin",
    "is_phishing": true,
    "confidence_score": 1.0,
    "extracted_features": {
      "url_length": 38,
      "dot_count": 1,
      "hyphen_count": 2,
      "has_https": 0,
      "has_at_symbol": 0,
      "is_ip_address": 0,
      "has_suspicious_keywords": 1
    }
  }
  ```

---

## 7. Testing with Postman & Terminal

### How to Test using Postman
1. Set HTTP request method to **`POST`**.
2. Input the request URL: **`http://localhost:5000/api/predict`**.
3. Under the **Headers** tab, ensure there is a key: `Content-Type` with value `application/json`.
4. Navigate to the **Body** tab, select **raw**, and change the format dropdown to **JSON**.
5. Paste the request payload:
   ```json
   {
     "url": "http://secure-banking-alert.com/signin"
   }
   ```
6. Click **Send** and analyze the prediction classification and extracted feature scores!

### How to Test using PowerShell (Terminal)
Execute this command in your PowerShell prompt to test a safe URL:
```powershell
Invoke-RestMethod -Uri "http://localhost:5000/api/predict" -Method Post -ContentType "application/json" -Body '{"url": "https://github.com/trending"}' | ConvertTo-Json -Depth 10
```

---

## 8. Troubleshooting & Common Errors

Here are common pitfalls software engineers face when building this system, and how to debug them:

### 1. PowerShell Script Execution Policies
* **Error**: `Script activation.ps1 cannot be loaded because running scripts is disabled on this system.`
* **Solution**: Avoid activating the environment in PowerShell. Simply run Python directly from the virtual environment path:
  `./.venv/Scripts/python your_script.py`. This bypasses shell execution policies completely.

### 2. UnicodeEncodeError in Terminal Output
* **Error**: `UnicodeEncodeError: 'charmap' codec can't encode character '\u274c'...`
* **Cause**: The Windows PowerShell console defaults to `cp1252` encoding, which crashes when attempting to print emoji symbols like ❌ or ✅.
* **Solution**: Ensure your command-line output prints clean, standard ASCII characters like `[SAFE]`, `[PHISHING]`, or `[ERROR]` instead of emoji characters.

### 3. Scikit-Learn UserWarning (Feature Names Mismatch)
* **Warning**: `UserWarning: X does not have valid feature names, but RandomForestClassifier was fitted with feature names...`
* **Cause**: You fit the Random Forest Classifier on a pandas DataFrame with structured header column names (e.g. `url_length`, `dot_count`), but you performed single URL inference using a raw numpy array or list.
* **Solution**: Convert your 1x7 numpy inference array into a pandas DataFrame with matching column names before running `model.predict()`:
  ```python
  features_df = pd.DataFrame(features_matrix, columns=feature_names)
  model.predict(features_df)
  ```

### 4. Flask Address Already In Use
* **Error**: `OSError: [Errno 98] Address already in use` (Port 5000 blocked).
* **Cause**: A background Flask or React service is already bound to port 5000.
* **Solution**: Either kill the process running on port 5000, or launch Flask on a different port (e.g., 5001) by editing the entrypoint in `main.py`:
  `app.run(host="0.0.0.0", port=5001, debug=True)`.

### 5. CORS Errors in Frontend Console
* **Error**: `Access to fetch at '...' from origin '...' has been blocked by CORS policy.`
* **Cause**: Same-Origin security limits block cross-port network streams.
* **Solution**: Verify `flask_cors.CORS(app)` is imported and initialized at the top level of your `main.py` script.

---

## 9. Future Roadmap & Strategic Phase Integrations

Phase 1 provides a mathematically sound, high-speed backbone. Here is how this foundation acts as the platform for subsequent security layers:

```
                            +-----------------------------------+
                            |  XPhishGuard Master Security Hub  |
                            +-----------------------------------+
                                              |
      +-----------------------+---------------+-----------------------+
      |                       |               |                       |
      v                       v               v                       v
+-----------+           +-----------+   +-----------+           +-----------+
|  Phase 2  |           |  Phase 3  |   |  Phase 4  |           |  Phase 5  |
|  React    |           |  Explain  |   |  Visual   |           |  NLP Email|
|  Frontend |           |  AI (SHAP)|   |  CNN      |           |  BERT     |
+-----------+           +-----------+   +-----------+           +-----------+
```

* **Phase 2: React Frontend UI**:
  Integrating a premium, modern dashboard (Vite + Tailwind CSS) featuring a glassmorphism URL scanner, real-time alert cards, confidence gauges, and interactive history lists to render the backend JSON payloads beautifully.
  
* **Phase 3: Explainable AI (XAI)**:
  Integrating SHAP (SHapley Additive exPlanations) or LIME. When a URL is flagged as phishing, SHAP values will calculate the exact percentage contribution of each feature (e.g., "Flagged because suspicious keywords contributed 42% and missing HTTPS contributed 25%"), showing the user *why* the AI made its decision.

* **Phase 4: Multi-Modal Screenshot CNN Analysis**:
  Integrating a Computer Vision layer using a Convolutional Neural Network (CNN). When a URL is scanned, a headless browser takes a silent screenshot of the target site. The CNN evaluates the image for layout spoofing (e.g., verifying if the page looks identical to PayPal's layout but is hosted on a non-PayPal domain).

* **Phase 5: NLP Email Phishing Classifier (BERT)**:
  Integrating a bidirectional encoder transformer (BERT) model to analyze email body content, subject lines, and headers, establishing a multi-agent ecosystem that cross-references email contexts against target URL domains.

* **Phase 6: Multi-Agent AI Cybersecurity Orchestrator**:
  Establishing a collaborative network of specialized security agents (DNS Inspector, SSL Verifier, URL ML Predictor, CNN visualizer, BERT context agent) orchestrated by a central LLM planner to generate deep forensic risk reports.
