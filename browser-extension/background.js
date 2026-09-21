import { analyzeUrl } from './service.js';
import { saveToHistory } from './utils.js';

chrome.runtime.onInstalled.addListener(() => {
  console.log("[XPhishGuard Background] Extension Installed");
  chrome.contextMenus.create({
    id: "analyze-url",
    title: "Analyze with XPhishGuard AI",
    contexts: ["link", "page"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "analyze-url") {
    const targetUrl = info.linkUrl || info.pageUrl;
    console.log("[XPhishGuard Background] Context Menu clicked for URL:", targetUrl);
    analyzeAndNotify(targetUrl);
  }
});

const notifiedDomains = new Set();
const tabLastDomain = {};
const ignoredPrefixes = ['chrome://', 'edge://', 'about:', 'file://'];
const ignoredDomains = ['localhost', '127.0.0.1'];

function getDomain(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return "";
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    if (ignoredPrefixes.some(prefix => tab.url.startsWith(prefix))) return;
    
    const domain = getDomain(tab.url);
    if (!domain || ignoredDomains.includes(domain)) return;

    if (tabLastDomain[tabId] !== domain) {
      tabLastDomain[tabId] = domain;
      console.log("[XPhishGuard Background] Auto-scanning active tab URL:", tab.url);
      analyzeUrlSilently(tab.url, tabId, domain);
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabLastDomain[tabId];
});

async function analyzeUrlSilently(url, tabId, domain) {
  try {
    const result = await analyzeUrl(url);
    if (result && result.success) {
      console.log("[XPhishGuard Background] Background scan success for:", url);
      updateBadge(result, tabId);
      
      const riskScore = result.risk_scorecard?.overall_risk || 0;
      if (riskScore >= 71) {
        if (domain && !notifiedDomains.has(domain)) {
          showAutoNotification(result, domain);
          notifiedDomains.add(domain);
        }
      }
      
      saveToHistory(result);
    } else {
      console.warn("[XPhishGuard Background] Background scan returned success: false", result);
    }
  } catch (err) {
    console.error("[XPhishGuard Background] Background analysis failed:", err);
  }
}

function updateBadge(result, tabId) {
  const isPhishing = result.is_phishing || false;
  const riskScore = result.risk_scorecard?.overall_risk || 0;
  
  let color = '#10b981'; // Green
  let text = 'SAFE';
  
  if (riskScore >= 80 || isPhishing) {
    color = '#ef4444'; // Red
    text = 'HIGH';
  } else if (riskScore >= 60) {
    color = '#f97316'; // Orange
    text = 'MED';
  } else if (riskScore >= 30) {
    color = '#f59e0b'; // Yellow
    text = 'LOW';
  }
  
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text, tabId });
}

function showAutoNotification(result, domain) {
  const riskScore = result.risk_scorecard?.overall_risk || 0;
  const attackType =
    result.attack_classification?.primary_attack_type || "Unknown";

  chrome.notifications.create(
    "xphishguard-" + Date.now(),
    {
      type: "basic",
      iconUrl: "icons/icon128.png",
      title: "🛡 XPhishGuard AI",
      message:
        `⚠ High Risk Website Detected\n\n` +
        `Website: ${domain}\n` +
        `Risk Score: ${riskScore}%\n` +
        `Attack Type: ${attackType}\n\n` +
        `Recommendation: Avoid entering credentials.`
    },
    (notificationId) => {
      if (chrome.runtime.lastError) {
        console.error(
          "Notification Error:",
          chrome.runtime.lastError.message
        );
      } else {
        console.log(
          "Notification shown successfully:",
          notificationId
        );
      }
    }
  );
}

function showNotification(result) {
  const riskScore = result.risk_scorecard?.overall_risk || 0;
  const attackType = result.attack_classification?.primary_attack_type || 'Phishing';
  const conf = result.confidence_score || 0;
  
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: 'XPhishGuard AI Alert',
    message: `High risk detected (${riskScore}%)! Confidence: ${(conf*100).toFixed(1)}%\nType: ${attackType}`,
    priority: 2
  });
}

async function analyzeAndNotify(url) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: 'XPhishGuard AI',
    message: 'Analyzing URL...',
  });
  
  try {
    const result = await analyzeUrl(url);
    if(result && result.success) {
        showNotification(result);
    } else {
        throw new Error(result?.error || 'Unknown Backend Error');
    }
  } catch (err) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'Analysis Failed',
      message: err.message
    });
  }
}
