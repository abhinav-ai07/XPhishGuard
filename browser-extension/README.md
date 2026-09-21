# XPhishGuard AI — Browser Extension (Manifest V3)

Real-time, AI-driven phishing detection assistant for Chromium-based browsers (Chrome, Edge, Brave, Opera). It inspects active web tabs and links using the XPhishGuard Flask backend, displaying threat level gauges, attack type classifications, brand spoof warnings, and plain-English explainable AI (SHAP) breakdowns.

---

## Key Features

- **Automated Active Tab Scanning**: Seamlessly inspects active web page URLs as you browse.
- **Glassmorphism Cyber SOC UI**: High-contrast, dark-mode popup displaying risk score gauges, confidence metrics, and technical dossiers.
- **Explainable AI (XAI) Reasoning**: Real-time SHAP feature impact cards explaining why a URL was marked safe or malicious.
- **Attack Classification & Brand Detection**: Unmasks phishing techniques (Credential Harvesting, Fake Login, Typosquatting) and target brands (e.g. PayPal, Google, Netflix).
- **Context Menu Inspection**: Right-click any hyperlink on any web page and select *"Analyze with XPhishGuard AI"* to inspect links before clicking them.
- **Instant Desktop Notifications**: Triggers immediate OS-level security warnings upon navigating to high-risk domains.

---

## Installation & Setup

### 1. Ensure Backend is Running
The extension communicates with the local XPhishGuard Flask server. Make sure the backend is active on `http://localhost:5000`:
```bash
# In the repository root or backend folder:
python backend/main.py
```

### 2. Load the Extension in your Browser
1. Open Google Chrome (or any Chromium browser like Microsoft Edge, Brave, etc.).
2. Navigate to `chrome://extensions/` (or `edge://extensions/`).
3. Turn on **Developer mode** toggle in the top-right corner.
4. Click **Load unpacked** in the top-left toolbar.
5. In the file picker dialog, select the `browser-extension` folder inside `XPhishGuard`.
6. Pin the **XPhishGuard AI** icon to your browser toolbar for easy access.

---

## File Structure

```
browser-extension/
├── icons/              # Extension icons in standard resolutions (16x16, 48x48, 128x128)
├── manifest.json       # Chrome Manifest V3 manifest specification and permissions
├── background.js       # Background service worker (context menus, notifications, tab monitoring)
├── content.js          # In-page script integration
├── popup.html          # Interactive extension popup modal
├── popup.css           # Glassmorphism cyber-security design stylesheet
├── popup.js            # Frontend logic and DOM rendering for the popup
├── service.js          # Backend API gateway integration (`/api/health`, `/api/predict`)
├── utils.js            # URL formatting, risk styling, and local history helpers
└── README.md           # Extension documentation
```
