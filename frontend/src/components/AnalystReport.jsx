import React, { useRef } from 'react';
import { FileText, Copy, Printer, Check, Shield } from 'lucide-react';
import clsx from 'clsx';

const AnalystReport = ({ result }) => {
  if (!result) return null;

  const { analyst_report, url, confidence_score, risk_level, triggered_signals } = result;
  const [copied, setCopied] = React.useState(false);
  const reportRef = useRef(null);

  if (!analyst_report) return null;

  const { threat_summary, risk_indicators = [], trust_indicators = [], ml_feature_analysis = [], final_verdict } = analyst_report;

  const handleCopy = () => {
    if (reportRef.current) {
      const text = reportRef.current.innerText;
      navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="glass-panel p-6 space-y-6 hover:border-gray-700 transition-all duration-300">
      {/* Report Header actions */}
      <div className="flex items-center justify-between border-b border-gray-800 pb-4">
        <div className="flex items-center space-x-2">
          <FileText className="w-5 h-5 text-brand" />
          <h3 className="text-sm font-extrabold uppercase tracking-wider text-gray-400">
            Threat Intelligence Report
          </h3>
        </div>

        <div className="flex items-center space-x-2">
          <button 
            onClick={handleCopy}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-gray-900 hover:bg-gray-800 text-xs font-mono border border-gray-800 text-gray-300 transition-colors"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-safe" />
                <span className="text-safe">Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Raw Text</span>
              </>
            )}
          </button>
          <button 
            onClick={handlePrint}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-gray-900 hover:bg-gray-800 text-xs font-mono border border-gray-800 text-gray-300 transition-colors"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print Report</span>
          </button>
        </div>
      </div>

      {/* The Printable Threat Report */}
      <div 
        ref={reportRef} 
        className="bg-[#08080c] p-6 rounded-lg border border-gray-800/80 font-mono text-sm text-gray-300 space-y-6 relative overflow-hidden"
      >
        {/* Background shield emblem */}
        <div className="absolute top-4 right-4 opacity-5 pointer-events-none">
          <Shield className="w-24 h-24 text-brand" />
        </div>

        {/* Audit Meta */}
        <div className="border-b border-gray-800 pb-4 space-y-1">
          <div className="text-xs text-gray-500 uppercase tracking-widest font-semibold">XPHISHGUARD AI THREAT INTEL SYSTEM</div>
          <div className="text-base font-extrabold text-white">SECURITY AUDIT ANALYSIS LOG</div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs text-gray-400 mt-3 pt-2 border-t border-gray-900">
            <div><strong>SCAN TARGET :</strong> {url}</div>
            <div><strong>TIMESTAMP   :</strong> {new Date().toISOString()}</div>
            <div><strong>VERDICT     :</strong> <span className={final_verdict === 'PHISHING' ? 'text-danger font-bold' : 'text-safe font-bold'}>{final_verdict}</span></div>
            <div><strong>RISK LEVEL  :</strong> {risk_level} (Conf: {(confidence_score*100).toFixed(1)}%)</div>
          </div>
        </div>

        {/* Section: Threat Summary */}
        <div className="space-y-2">
          <div className="text-xs font-extrabold text-brand uppercase tracking-wider">1. EXECUTIVE THREAT SUMMARY</div>
          <p className="text-xs text-gray-400 leading-relaxed pl-2 border-l-2 border-brand/50">
            {threat_summary}
          </p>
        </div>

        {/* Section: Indicators */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <div className="text-xs font-extrabold text-danger uppercase tracking-wider">2. DETECTED RISK INDICATORS</div>
            {risk_indicators.length > 0 ? (
              <ul className="list-inside list-disc text-xs text-gray-400 space-y-1 pl-1">
                {risk_indicators.map((risk, i) => (
                  <li key={i}>{risk}</li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-gray-500 italic pl-1">No indicators triggered.</p>
            )}
          </div>

          <div className="space-y-2">
            <div className="text-xs font-extrabold text-safe uppercase tracking-wider">3. DETECTED TRUST INDICATORS</div>
            {trust_indicators.length > 0 ? (
              <ul className="list-inside list-disc text-xs text-gray-400 space-y-1 pl-1">
                {trust_indicators.map((trust, i) => (
                  <li key={i}>{trust}</li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-gray-500 italic pl-1">No trust indicators matched.</p>
            )}
          </div>
        </div>

        {/* Section: ML Features */}
        <div className="space-y-2">
          <div className="text-xs font-extrabold text-brand uppercase tracking-wider">4. SHAP ML FEATURE CONTRIBUTION LOG</div>
          <div className="overflow-x-auto pl-2 border-l-2 border-brand/50">
            <table className="w-full text-xs text-left text-gray-400">
              <thead>
                <tr className="border-b border-gray-800 text-gray-500 font-bold uppercase">
                  <th className="py-2">FEATURE</th>
                  <th className="py-2 text-right">IMPACT</th>
                </tr>
              </thead>
              <tbody>
                {ml_feature_analysis.slice(0, 6).map((feat, i) => (
                  <tr key={i} className="border-b border-gray-900/40">
                    <td className="py-2 text-gray-300">`{feat.feature}`</td>
                    <td className={clsx(
                      "py-2 text-right font-bold",
                      feat.impact.startsWith("+") ? "text-danger" : "text-safe"
                    )}>
                      {feat.impact}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Section: Triggered Rules */}
        <div className="space-y-2">
          <div className="text-xs font-extrabold text-brand uppercase tracking-wider">5. TRIGGERED CYBERSECURITY RULES</div>
          {triggered_signals.length > 0 ? (
            <div className="flex flex-wrap gap-1.5 pl-1">
              {triggered_signals.map((sig, i) => (
                <span key={i} className="bg-surfaceHighlight/50 border border-gray-800 px-2 py-0.5 text-xs rounded text-white">
                  {sig}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs text-gray-500 italic pl-1">No security rules breached.</p>
          )}
        </div>

        {/* Signatures */}
        <div className="pt-6 border-t border-gray-900 text-xs text-gray-500 flex flex-col md:flex-row justify-between gap-4 font-mono">
          <div>Report ID: XPG-{url.slice(0, 10).toUpperCase().replace(/[^A-Z]/g, 'X')}-{Date.now().toString().slice(-6)}</div>
          <div>Authorized Signature: <strong>XPhishGuard Hybrid Audit Core</strong></div>
        </div>
      </div>
    </div>
  );
};

export default AnalystReport;
