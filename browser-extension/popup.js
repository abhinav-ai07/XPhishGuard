import { checkHealth, analyzeUrl } from './service.js';
import { getRiskColor, formatUrl } from './utils.js';

document.addEventListener('DOMContentLoaded', async () => {
  console.log("[XPhishGuard Popup] DOM Content Loaded");
  const urlDisplay = document.getElementById('url-display');
  const errorScreen = document.getElementById('error-screen');
  const mainContent = document.getElementById('main-content');
  const statusLabel = document.getElementById('status-label');
  const scanFrame = document.getElementById('scan-frame');
  const retryBtn = document.getElementById('retry-btn');
  const rescanBtn = document.getElementById('rescan-btn');
  const downloadBtn = document.getElementById('download-report-btn');
  const scanTimestamp = document.getElementById('scan-timestamp');

  // Elements to update
  const riskCircle = document.getElementById('risk-circle');
  const riskText = document.getElementById('risk-text');
  const riskLevel = document.getElementById('risk-level');
  const confidenceText = document.getElementById('confidence-text');
  const verdictBox = document.getElementById('verdict-box');
  const verdictTitle = document.getElementById('verdict-title');
  const verdictSubtitle = document.getElementById('verdict-subtitle');
  const whyTitle = document.getElementById('why-title');
  const shapList = document.getElementById('shap-list');
  const riskBreakdown = document.getElementById('risk-breakdown');
  const recsContainer = document.getElementById('recommendations');
  const dataRows = document.getElementById('data-rows');
  const investContainer = document.getElementById('investigation-report');

  let lastResult = null;
  let lastUrl = null;

  // Dossier (accordion) logic
  document.querySelectorAll('.dossier-btn').forEach(btn => {
    btn.addEventListener('click', function () {
      const content = this.nextElementSibling;
      const isOpen = content.style.display === 'block';
      content.style.display = isOpen ? 'none' : 'block';
      this.classList.toggle('open', !isOpen);
      this.querySelector('.dossier-toggle').textContent = isOpen ? '+' : '\u2212';
    });
  });

  function setStatus(state, label) {
    statusLabel.className = 'status-readout ' + state;
    statusLabel.innerHTML = `<span class="status-dot"></span> ${label}`;
  }

  async function init() {
    console.log("[XPhishGuard Popup] Initializing...");
    downloadBtn.disabled = true;
    lastResult = null;
    scanTimestamp.textContent = '';
    scanFrame.className = 'scan-frame';
    try {
      setStatus('checking', 'Checking Backend...');
      await checkHealth();
      console.log("[XPhishGuard Popup] Backend health check passed");
      errorScreen.classList.add('hidden');
      mainContent.classList.remove('hidden');

      chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        let currentUrl = tabs[0].url;
        console.log("[XPhishGuard Popup] Active Tab URL:", currentUrl);
        if (!currentUrl || currentUrl.startsWith('chrome://') || currentUrl.startsWith('edge://')) {
          urlDisplay.textContent = 'Invalid or internal browser page';
          setStatus('error', 'Unsupported Page');
          console.warn("[XPhishGuard Popup] URL is invalid for scanning:", currentUrl);
          return;
        }

        lastUrl = currentUrl;
        urlDisplay.textContent = formatUrl(currentUrl);
        urlDisplay.title = currentUrl;
        await performAnalysis(currentUrl);
      });

    } catch (e) {
      console.error("[XPhishGuard Popup] Initialization failed:", e);
      setStatus('error', 'Backend Offline');
      mainContent.classList.add('hidden');
      errorScreen.classList.remove('hidden');
      const errP = errorScreen.querySelector('p');
      if (errP) errP.textContent = e.message;
    }
  }

  async function performAnalysis(url) {
    console.log("[XPhishGuard Popup] performAnalysis called for:", url);
    setStatus('checking', 'Scanning Website...');
    scanFrame.className = 'scan-frame scanning';
    try {
      const result = await analyzeUrl(url);
      console.log("[XPhishGuard Popup] Got valid result object:", result);
      lastResult = result;
      renderResult(result);
    } catch (e) {
      console.error("[XPhishGuard Popup] performAnalysis caught exception:", e);
      urlDisplay.textContent = 'Analysis Failed';
      verdictTitle.textContent = 'ERROR';
      verdictTitle.style.color = 'var(--threat)';
      verdictSubtitle.textContent = e.message;
      setStatus('error', 'Error');
      scanFrame.className = 'scan-frame';
    }
  }

  function renderResult(result) {
    console.log("[XPhishGuard Popup] renderResult started");
    try {
      const isPhish = result.is_phishing || false;
      const riskScore = result.risk_scorecard?.overall_risk || 0;
      const confidence = result.confidence_score !== undefined ? result.confidence_score : 0;
      
      const color = getRiskColor(riskScore);

      // SECTION 2: Meter
      riskCircle.style.strokeDasharray = `${riskScore}, 100`;
      riskCircle.style.stroke = color;
      riskText.textContent = `${riskScore}%`;
      riskText.style.color = color;
      
      let riskLevelTxt = "SAFE";
      if (riskScore > 20) riskLevelTxt = "SUSPICIOUS";
      if (riskScore >= 60) riskLevelTxt = "HIGH RISK";
      if (riskScore >= 80) riskLevelTxt = "DANGEROUS";
      
      if (riskLevel) {
          riskLevel.textContent = riskLevelTxt;
          riskLevel.style.color = color;
      }
      if (confidenceText) {
          confidenceText.textContent = `${(confidence * 100).toFixed(0)}%`;
      }

      scanFrame.className = 'scan-frame locked ' + (isPhish ? 'danger' : 'safe');

      setStatus('ok', 'Backend Online');

      // SECTION 3: Verdict Card
      const analystSummary = result.analyst_summary || "Scan complete.";
      if (isPhish) {
          verdictTitle.textContent = "🚨 High Risk Phishing Website";
      } else if (riskScore > 20) {
          verdictTitle.textContent = "⚠ Suspicious Website";
      } else {
          verdictTitle.textContent = "✅ Safe to Browse";
      }
      verdictTitle.style.color = color;
      verdictSubtitle.textContent = analystSummary;
      verdictBox.style.borderLeftColor = color;
      
      // SECTION 4: Why did AI give this score?
      whyTitle.textContent = isPhish ? "Why is this website dangerous?" : "Why is this website considered safe?";
      shapList.innerHTML = '';
      if (result.top_contributors && result.top_contributors.length > 0) {
          const top5 = result.top_contributors.slice(0, 5);
          top5.forEach(contrib => {
              // SHAP impact negative indicates reducing risk (safe)
              const isPositive = contrib.impact.startsWith('-'); 
              const impactColor = isPositive ? 'var(--ok)' : 'var(--threat)';
              const icon = isPositive ? '✔' : '⚠';
              const readableName = contrib.feature.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
              
              shapList.innerHTML += `
                  <div class="shap-item">
                      <div class="shap-name">
                          <span class="shap-icon" style="color: ${impactColor}">${icon}</span>
                          ${readableName}
                      </div>
                      <div class="shap-impact" style="color: ${impactColor}">${contrib.impact}</div>
                  </div>
              `;
          });
      } else {
          shapList.innerHTML = '<div style="color:var(--fog); font-size:0.75rem;">No AI reasoning available.</div>';
      }

      // SECTION 5: Risk Breakdown
      riskBreakdown.innerHTML = '';
      if (result.risk_scorecard) {
          const breakdownCats = [
              { label: 'Brand Impersonation', key: 'brand_impersonation' },
              { label: 'URL Structure', key: 'url_structure' },
              { label: 'Domain Reputation', key: 'domain_reputation' }
          ];
          
          breakdownCats.forEach(cat => {
              const val = result.risk_scorecard[cat.key] || 0;
              let barColor = 'var(--slate)';
              if (val > 60) barColor = 'var(--threat)';
              else if (val > 20) barColor = 'var(--signal)';
              else barColor = 'var(--ok)';
              
              riskBreakdown.innerHTML += `
                  <div class="bar-row">
                      <div class="bar-header">
                          <span>${cat.label}</span>
                          <span class="bar-val" style="color: ${barColor}">${val}%</span>
                      </div>
                      <div class="bar-visual">
                          <div class="bar-fill" style="width: ${val}%; background: ${barColor};"></div>
                      </div>
                  </div>
              `;
          });
      }

      // SECTION 6: Recommendations
      recsContainer.style.display = 'block';
      if (isPhish) {
          recsContainer.style.background = 'var(--threat-dim)';
          recsContainer.style.borderLeftColor = 'var(--threat)';
          recsContainer.innerHTML = `
              <ul style="color: var(--paper)">
                  <li>Avoid entering passwords.</li>
                  <li>Close this tab.</li>
                  <li>Do not download files.</li>
                  <li>Report website.</li>
              </ul>
          `;
      } else {
          recsContainer.style.background = 'var(--ok-dim)';
          recsContainer.style.borderLeftColor = 'var(--ok)';
          recsContainer.style.borderColor = 'rgba(87, 189, 140, 0.3)';
          recsContainer.innerHTML = `
              <ul style="color: var(--paper)">
                  <li>Continue browsing safely.</li>
                  <li>Use HTTPS whenever possible.</li>
                  <li>Keep browser updated.</li>
              </ul>
          `;
      }

      // SECTION 7: Technical Details
      dataRows.innerHTML = '';
      const addRow = (label, val, valColor) => {
        dataRows.innerHTML += `
          <tr>
            <td class="dt-label">${label}</td>
            <td class="dt-value" style="color: ${valColor || 'var(--paper)'}">${val}</td>
          </tr>
        `;
      };

      const primaryAttackType = result.attack_classification?.primary_attack_type || 'None';
      const brandTarget = result.brand_detection?.likely_target_brand || 'None';
      
      addRow('Attack Type', primaryAttackType, isPhish ? 'var(--threat)' : 'var(--ok)');
      addRow('Brand Target', brandTarget);
      addRow('Raw Risk Score', riskScore + '%');
      addRow('Raw Confidence', (confidence * 100).toFixed(1) + '%');

      if (investContainer) {
          const report = result.full_analyst_report;
          if (report) {
             investContainer.innerHTML = `
                <h4>Executive Summary</h4>
                <p>${analystSummary}</p>
                <h4>Model Prediction</h4>
                <p>${isPhish ? 'Phishing Detected' : 'Safe'} (Confidence: ${(confidence * 100).toFixed(1)}%)</p>
                <h4>Top ML Features</h4>
                <ul>
                   ${result.top_contributors ? result.top_contributors.slice(0,3).map(c => `<li>${c.feature.replace(/_/g, ' ')}: ${c.impact}</li>`).join('') : 'None'}
                </ul>
                ${isPhish ? `<h4>MITRE ATT&CK Mapping</h4><p>T1566 - Phishing</p>` : ''}
                <h4>Recommended Actions</h4>
                <p>${result.recommendations && result.recommendations.length ? result.recommendations.join(', ') : 'None'}</p>
             `;
          } else {
             investContainer.innerHTML = '<p>No investigation report generated.</p>';
          }
      }

      downloadBtn.disabled = false;
      const now = new Date();
      scanTimestamp.textContent = `Scanned ${now.toLocaleString()}`;

      console.log("[XPhishGuard Popup] renderResult completed successfully");
    } catch (renderError) {
      console.error("[XPhishGuard Popup] Rendering Error:", renderError);
      urlDisplay.textContent = 'Rendering Failed';
    }
  }

  // ---------- Download Report ----------
  function buildReportText(result, url) {
    const isPhish = result.is_phishing || false;
    const riskScore = result.risk_scorecard?.overall_risk || 0;
    const confidence = result.confidence_score !== undefined ? result.confidence_score : 0;
    
    const primaryAttackType = result.attack_classification?.primary_attack_type || 'None';
    const brandTarget = result.brand_detection?.likely_target_brand || 'None';
    const trustedDomain = result.extracted_features?.is_trusted_domain;
    const explanations = result.human_explanations || [];
    const recommendations = result.recommendations || [];

    const line = (ch = '-') => ch.repeat(48);
    const lines = [];
    
    lines.push('XPHISHGUARD AI — ANALYSIS REPORT');
    lines.push(line('='));
    lines.push(`Generated:    ${new Date().toLocaleString()}`);
    lines.push(`Scanned URL:  ${url || 'Unknown'}`);
    lines.push('');
    lines.push('VERDICT');
    lines.push(line());
    lines.push(`Result:       ${isPhish ? 'DANGEROUS — Likely Phishing' : 'SAFE — No Threat Detected'}`);
    lines.push(`Risk Score:   ${riskScore}%`);
    lines.push(`Confidence:   ${(confidence * 100).toFixed(1)}%`);
    lines.push('');
    lines.push('THREAT SUMMARY');
    lines.push(line());
    lines.push(`Attack Type:      ${primaryAttackType}`);
    lines.push(`Brand Target:     ${brandTarget}`);
    lines.push(`Domain Reputation: ${trustedDomain ? 'TRUSTED' : 'UNKNOWN'}`);
    lines.push('');
    lines.push('EXPLAINABLE AI — WHY THIS VERDICT');
    lines.push(line());
    if (explanations.length > 0) {
      explanations.forEach((e, i) => lines.push(`${i + 1}. ${e.message}`));
    } else {
      lines.push('No AI explanations available.');
    }
    lines.push('');
    lines.push('RECOMMENDED ACTIONS');
    lines.push(line());
    if (recommendations.length > 0) {
      recommendations.forEach((r, i) => lines.push(`${i + 1}. ${r}`));
    } else {
      lines.push('No specific actions recommended.');
    }
    lines.push('');
    lines.push(line('='));
    lines.push('Generated by XPhishGuard AI browser extension.');

    return lines.join('\n');
  }

  function downloadReport() {
    if (!lastResult) return;
    const text = buildReportText(lastResult, lastUrl);
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);

    const safeHost = (() => {
      try { return new URL(lastUrl).hostname.replace(/[^a-z0-9.-]/gi, '_'); }
      catch { return 'report'; }
    })();
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');

    const a = document.createElement('a');
    a.href = url;
    a.download = `xphishguard-report-${safeHost}-${stamp}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  downloadBtn.addEventListener('click', downloadReport);
  retryBtn.addEventListener('click', init);
  rescanBtn.addEventListener('click', init);

  init();
});