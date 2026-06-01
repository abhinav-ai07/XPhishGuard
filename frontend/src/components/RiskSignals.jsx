import React from 'react';
import { Eye, ArrowRight, ShieldCheck, ShieldAlert, CircleDot, AlertOctagon } from 'lucide-react';
import clsx from 'clsx';

const RiskSignals = ({ result }) => {
  if (!result) return null;

  const { threat_timeline, analyst_report } = result;
  const { risk_indicators = [], trust_indicators = [] } = analyst_report || {};

  return (
    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
      {/* Chronological Timeline - Left (7 Columns) */}
      <div className="lg:col-span-7 glass-panel p-6 space-y-4 hover:border-gray-700 transition-all duration-300">
        <div className="flex items-center space-x-2 border-b border-gray-800 pb-3">
          <Eye className="w-5 h-5 text-brand" />
          <h3 className="text-sm font-extrabold uppercase tracking-wider text-gray-400">
            Threat Reasoning Timeline (Chronological)
          </h3>
        </div>

        {/* Timeline Path */}
        <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-[2px] before:bg-gray-800/80">
          {threat_timeline && threat_timeline.length > 0 ? (
            threat_timeline.map((step, idx) => {
              const isML = step.event.includes("ML");
              const isOver = step.event.includes("Rules");
              
              return (
                <div key={idx} className="relative group">
                  {/* Timeline Node Icon */}
                  <div className={clsx(
                    "absolute -left-[22px] top-1.5 w-3.5 h-3.5 rounded-full border-2 transition-transform duration-300 group-hover:scale-125 z-10",
                    isML ? "bg-brand border-brand" :
                    isOver ? "bg-danger border-danger" :
                    "bg-background border-gray-600"
                  )} />

                  <div className="bg-surfaceHighlight/20 p-3 rounded-lg border border-gray-800/50 hover:border-gray-800 transition-colors duration-200">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-bold text-gray-400 uppercase tracking-wide">
                        Step {step.step}: {step.event}
                      </span>
                      {isML && <span className="text-[10px] bg-brand/10 text-brand px-1.5 py-0.5 rounded font-mono font-bold border border-brand/20">Machine Learning</span>}
                      {isOver && <span className="text-[10px] bg-danger/10 text-danger px-1.5 py-0.5 rounded font-mono font-bold border border-danger/20">Cybersecurity Engine</span>}
                    </div>
                    <p className="text-sm text-gray-300 font-mono leading-relaxed">
                      {step.details}
                    </p>
                  </div>
                </div>
              );
            })
          ) : (
            <p className="text-sm text-gray-500 font-mono italic">No threat timeline available.</p>
          )}
        </div>
      </div>

      {/* Signals Breakdown - Right (5 Columns) */}
      <div className="lg:col-span-5 flex flex-col gap-6">
        {/* Risk Indicators Card */}
        <div className="glass-panel p-6 space-y-4 hover:border-gray-700 transition-all duration-300 flex-1">
          <div className="flex items-center space-x-2 border-b border-gray-800 pb-3">
            <AlertOctagon className="w-5 h-5 text-danger" />
            <h3 className="text-sm font-extrabold uppercase tracking-wider text-gray-400">
              Risk Indicators
            </h3>
          </div>
          
          <div className="space-y-3 max-h-[220px] overflow-y-auto pr-1">
            {risk_indicators.length > 0 ? (
              risk_indicators.map((risk, idx) => (
                <div key={idx} className="flex items-start space-x-2.5 bg-danger/5 p-3 rounded border border-danger/15 text-xs text-danger font-sans">
                  <ShieldAlert className="w-4 h-4 text-danger flex-shrink-0 mt-0.5" />
                  <span className="leading-relaxed font-semibold">{risk}</span>
                </div>
              ))
            ) : (
              <div className="text-center py-4 bg-gray-900/10 border border-gray-800 rounded font-mono text-xs text-gray-500 italic">
                No major risk factors flagged.
              </div>
            )}
          </div>
        </div>

        {/* Trust Anchors Card */}
        <div className="glass-panel p-6 space-y-4 hover:border-gray-700 transition-all duration-300 flex-1">
          <div className="flex items-center space-x-2 border-b border-gray-800 pb-3">
            <ShieldCheck className="w-5 h-5 text-safe" />
            <h3 className="text-sm font-extrabold uppercase tracking-wider text-gray-400">
              Trust Anchors
            </h3>
          </div>
          
          <div className="space-y-3 max-h-[220px] overflow-y-auto pr-1">
            {trust_indicators.length > 0 ? (
              trust_indicators.map((trust, idx) => (
                <div key={idx} className="flex items-start space-x-2.5 bg-safe/5 p-3 rounded border border-safe/15 text-xs text-safe font-sans">
                  <ShieldCheck className="w-4 h-4 text-safe flex-shrink-0 mt-0.5" />
                  <span className="leading-relaxed font-semibold">{trust}</span>
                </div>
              ))
            ) : (
              <div className="text-center py-4 bg-gray-900/10 border border-gray-800 rounded font-mono text-xs text-gray-500 italic">
                No trust anchors detected.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default RiskSignals;
