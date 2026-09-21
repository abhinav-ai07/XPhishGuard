export function getRiskColor(score) {
  if (score < 30) return '#10b981'; // Green
  if (score < 60) return '#f59e0b'; // Yellow
  if (score < 80) return '#f97316'; // Orange
  return '#ef4444'; // Red
}

export function formatUrl(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname;
  } catch (e) {
    return url;
  }
}

export async function saveToHistory(report) {
  chrome.storage.local.get(['history'], (res) => {
    let history = res.history || [];
    // Remove if exists
    history = history.filter(h => h.url !== report.url);
    history.unshift(report);
    // Keep last 20
    if (history.length > 20) history = history.slice(0, 20);
    chrome.storage.local.set({ history });
  });
}
