# XPhishGuard AI — Cyber SOC Frontend Dashboard

A modern, high-performance Security Operations Center (SOC) dashboard built with **React 19**, **Vite**, and **Tailwind CSS**. It connects to the XPhishGuard Flask backend to visualize phishing predictions, SHAP explainability waterfall/force charts, brand spoofing diagnostics, and model auditing.

---

## Features

- **Real-Time URL Scanner**: Enter any suspicious link to get immediate verdict (Safe / Suspicious / High Risk / Dangerous).
- **Explainable AI (XAI) Explanations**: Human-readable natural language breakdown explaining *why* a URL was flagged.
- **Visual XAI Charts**: Render SHAP local importance, waterfall plots, and force plots directly in the browser.
- **Threat Intelligence Feed**: Aggregated live detection signals from VirusTotal, PhishTank, OpenPhish, and URLHaus.
- **XAI Model Auditing**: Interactive section to inspect global model bias, feature correlations, and fairness audits.

---

## Quickstart Guide

### 1. Prerequisites
- **Node.js**: v18.0 or higher
- **npm** or **yarn**
- **XPhishGuard Backend** running on `http://localhost:5000`

### 2. Install Dependencies
```bash
npm install
```

### 3. Start Development Server
```bash
npm run dev
```
The application will start at `http://localhost:5173`.

### 4. Build for Production
```bash
npm run build
```
Builds the static application to the `dist/` directory.

### 5. Preview Production Build
```bash
npm run preview
```

---

## Configuration

By default, the frontend sends requests to `http://localhost:5000/api`. You can override this by creating a `.env` file in the `frontend/` directory:

```env
VITE_API_URL=http://localhost:5000/api
```
