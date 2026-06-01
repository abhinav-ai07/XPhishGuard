import React, { useState, useEffect } from 'react';
import { ShieldCheck, BarChart3, HelpCircle, Activity, GitBranch, RefreshCw, Layers } from 'lucide-react';
import axios from 'axios';
import clsx from 'clsx';

const ModelAuditReport = () => {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('summary'); // summary, shap_global, correlations, bias

  const fetchAuditData = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await axios.get('http://localhost:5000/api/audit');
      if (response.data.success) {
        setData(response.data);
      } else {
        throw new Error(response.data.error || 'Failed to fetch audit data');
      }
    } catch (err) {
      setError(err.message || 'Error communicating with Flask audit endpoint.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAuditData();
  }, []);

  if (loading) {
    return (
      <div className="glass-panel p-8 text-center space-y-4">
        <RefreshCw className="w-8 h-8 text-brand animate-spin mx-auto" />
        <p className="text-sm font-mono text-gray-400">Loading global model audit metrics from Flask...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass-panel p-8 border-danger/30 text-center space-y-2">
        <p className="text-sm font-mono text-danger font-bold">AUDIT ERROR: {error}</p>
        <button 
          onClick={fetchAuditData}
          className="mt-2 px-3 py-1.5 bg-danger/10 hover:bg-danger/25 text-danger font-mono text-xs rounded border border-danger/20 transition-colors"
        >
          Retry Audit Retrieval
        </button>
      </div>
    );
  }

  if (!data) return null;

  const { report, plots } = data;
  const { top_features = [], bias_indicators = {}, feature_dominance = [], error_analysis = {} } = report;

  return (
    <div className="w-full space-y-6">
      {/* Tab bar header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-3">
        <div>
          <h2 className="text-2xl font-black text-white tracking-tight flex items-center space-x-2">
            <Layers className="w-6 h-6 text-brand" />
            <span>XAI Global Model Auditing Core</span>
          </h2>
          <p className="text-xs text-gray-500 font-mono mt-1">
            Analyzing training shortcuts, feature alignments, and structural class bias.
          </p>
        </div>

        {/* Audit Tabs */}
        <div className="flex bg-surfaceHighlight p-1 rounded-lg border border-gray-800 text-xs font-semibold">
          {[
            { id: 'summary', label: 'Feature Importance' },
            { id: 'shap_global', label: 'Global SHAP Plot' },
            { id: 'correlations', label: 'Feature Correlations' },
            { id: 'bias', label: 'Bias & Errors' }
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={clsx(
                "px-3 py-1.5 rounded transition-all duration-200",
                activeTab === tab.id
                  ? "bg-brand text-background font-bold shadow-md shadow-brand/10"
                  : "text-gray-400 hover:text-gray-200"
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Contents */}
      {activeTab === 'summary' && (
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
          {/* Top Features (7 Columns) */}
          <div className="md:col-span-7 glass-panel p-6 space-y-4">
            <h3 className="text-sm font-extrabold uppercase tracking-wider text-gray-400 border-b border-gray-800 pb-3 flex items-center">
              <BarChart3 className="w-4 h-4 text-brand mr-2" />
              Global Feature Importance (SHAP Absolute Averages)
            </h3>
            <div className="space-y-3 font-mono text-xs">
              {top_features.map((item, idx) => (
                <div key={idx} className="space-y-1">
                  <div className="flex justify-between text-gray-300">
                    <span>{idx + 1}. `{item.feature}`</span>
                    <span className="text-brand font-bold">{item.importance}</span>
                  </div>
                  {/* Bar graphic */}
                  <div className="w-full bg-gray-900 rounded-full h-1.5 overflow-hidden">
                    <div 
                      className="bg-brand h-full rounded-full" 
                      style={{ width: `${parseFloat(item.importance)}%` }} 
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Feature Dominance (5 Columns) */}
          <div className="md:col-span-5 flex flex-col gap-6">
            <div className="glass-panel p-6 space-y-4 flex-1">
              <h3 className="text-sm font-extrabold uppercase tracking-wider text-gray-400 border-b border-gray-800 pb-3 flex items-center">
                <GitBranch className="w-4 h-4 text-brand mr-2" />
                Feature Dominance (Decision Drivers)
              </h3>
              <p className="text-xs text-gray-500 font-mono">
                Measures how often a feature acts as the single largest contributor to prediction outcome:
              </p>
              <div className="space-y-3 pt-2">
                {feature_dominance.map((item, idx) => (
                  <div key={idx} className="flex justify-between items-center bg-surfaceHighlight/30 p-2.5 rounded border border-gray-800/80 font-mono text-xs text-gray-300">
                    <div>
                      <span className="text-gray-500 mr-2">{idx+1}.</span>
                      <strong>`{item.feature}`</strong>
                    </div>
                    <span className="bg-brand/10 text-brand px-2 py-0.5 rounded font-bold">{item.percentage} of cases</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'shap_global' && (
        <div className="glass-panel p-6 space-y-4">
          <h3 className="text-sm font-extrabold uppercase tracking-wider text-gray-400 border-b border-gray-800 pb-3 flex items-center">
            <Activity className="w-4 h-4 text-brand mr-2" />
            Global SHAP Summary Plot
          </h3>
          <p className="text-xs text-gray-500 font-mono">
            Every point represents a dataset URL prediction. Red indicates a high feature value, and blue indicates low.
            The horizontal position shows whether it increases risk (right) or decreases it (left).
          </p>
          <div className="bg-background/50 border border-gray-850 p-4 rounded-lg flex justify-center">
            {plots.global_summary_plot ? (
              <img 
                src={`data:image/png;base64,${plots.global_summary_plot}`} 
                alt="Global SHAP Plot" 
                className="max-h-[480px] object-contain rounded" 
              />
            ) : (
              <p className="text-xs font-mono text-gray-500 italic">Global plot not available.</p>
            )}
          </div>
        </div>
      )}

      {activeTab === 'correlations' && (
        <div className="glass-panel p-6 space-y-4">
          <h3 className="text-sm font-extrabold uppercase tracking-wider text-gray-400 border-b border-gray-800 pb-3 flex items-center">
            <HelpCircle className="w-4 h-4 text-brand mr-2" />
            Feature Correlation Matrix
          </h3>
          <p className="text-xs text-gray-500 font-mono">
            Heatmap checking if features are highly correlated, highlighting potential feature redundancies or data leakage vectors.
          </p>
          <div className="bg-background/50 border border-gray-850 p-4 rounded-lg flex justify-center">
            {plots.feature_correlation ? (
              <img 
                src={`data:image/png;base64,${plots.feature_correlation}`} 
                alt="Feature Correlation Heatmap" 
                className="max-h-[480px] object-contain rounded" 
              />
            ) : (
              <p className="text-xs font-mono text-gray-500 italic">Correlation plot not available.</p>
            )}
          </div>
        </div>
      )}

      {activeTab === 'bias' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Bias detection */}
          <div className="glass-panel p-6 space-y-4">
            <h3 className="text-sm font-extrabold uppercase tracking-wider text-danger border-b border-gray-800 pb-3">
              Model Shortcut Bias Analysis
            </h3>
            <div className="space-y-4 pt-2">
              <div className="bg-surfaceHighlight/20 p-4 rounded border border-gray-800/80 space-y-2">
                <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">HTTPS Protocol Shortcut Check</span>
                <div className="flex justify-between items-baseline mt-1 font-mono text-xs">
                  <span className="text-gray-400">HTTPS prediction rate (phish %):</span>
                  <strong className="text-brand">{bias_indicators.https_vs_http?.https_phishing_prediction_rate}</strong>
                </div>
                <div className="flex justify-between items-baseline font-mono text-xs">
                  <span className="text-gray-400">HTTP prediction rate (phish %):</span>
                  <strong className="text-danger">{bias_indicators.https_vs_http?.http_phishing_prediction_rate}</strong>
                </div>
                <p className="text-[10px] text-gray-500 font-mono mt-2 leading-relaxed">
                  Low HTTPS classification rates indicate vulnerability to "HTTPS = Safe" adversarial exploits. Modern XPhishGuard mitigates this with payload rules.
                </p>
              </div>

              <div className="bg-surfaceHighlight/20 p-4 rounded border border-gray-800/80 space-y-2">
                <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">Risky TLD Shortcut Check</span>
                <div className="flex justify-between items-baseline mt-1 font-mono text-xs">
                  <span className="text-gray-400">Risky TLD prediction rate:</span>
                  <strong className="text-danger">{bias_indicators.risky_tld_vs_safe?.risky_tld_phishing_prediction_rate}</strong>
                </div>
                <div className="flex justify-between items-baseline font-mono text-xs">
                  <span className="text-gray-400">Safe TLD prediction rate:</span>
                  <strong className="text-safe">{bias_indicators.risky_tld_vs_safe?.safe_tld_phishing_prediction_rate}</strong>
                </div>
              </div>
            </div>
          </div>

          {/* Error analysis */}
          <div className="glass-panel p-6 space-y-4">
            <h3 className="text-sm font-extrabold uppercase tracking-wider text-amber-400 border-b border-gray-800 pb-3">
              False Positive & False Negative Profiling
            </h3>
            <div className="space-y-4 pt-2">
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-surfaceHighlight/20 p-3 rounded border border-gray-800 text-center font-mono">
                  <div className="text-[10px] text-gray-500">FALSE POSITIVES</div>
                  <div className="text-xl font-bold text-amber-500 mt-1">{error_analysis.false_positives_count}</div>
                  <div className="text-[9px] text-gray-500">sample validation</div>
                </div>
                <div className="bg-surfaceHighlight/20 p-3 rounded border border-gray-800 text-center font-mono">
                  <div className="text-[10px] text-gray-500">FALSE NEGATIVES</div>
                  <div className="text-xl font-bold text-danger mt-1">{error_analysis.false_negatives_count}</div>
                  <div className="text-[9px] text-gray-500">sample validation</div>
                </div>
              </div>

              {/* Contributing features */}
              <div className="space-y-3 font-mono text-xs">
                <div>
                  <span className="text-gray-400 font-bold block mb-1">Top triggers causing False Flags:</span>
                  {error_analysis.top_false_positive_contributors && Object.keys(error_analysis.top_false_positive_contributors).length > 0 ? (
                    Object.entries(error_analysis.top_false_positive_contributors).map(([feat, imp]) => (
                      <div key={feat} className="flex justify-between p-1 bg-surfaceHighlight/10 rounded px-2">
                        <span className="text-gray-300">`{feat}`</span>
                        <span className="text-danger font-bold">{imp}</span>
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-gray-500 italic">None detected.</p>
                  )}
                </div>

                <div>
                  <span className="text-gray-400 font-bold block mb-1">Top triggers causing Leakages (FNs):</span>
                  {error_analysis.top_false_negative_contributors && Object.keys(error_analysis.top_false_negative_contributors).length > 0 ? (
                    Object.entries(error_analysis.top_false_negative_contributors).map(([feat, imp]) => (
                      <div key={feat} className="flex justify-between p-1 bg-surfaceHighlight/10 rounded px-2">
                        <span className="text-gray-300">`{feat}`</span>
                        <span className="text-safe font-bold">{imp}</span>
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-gray-500 italic">None detected.</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ModelAuditReport;
