import React from 'react';
import { Brain, Shield, ShieldAlert, Sparkles, ChevronRight } from 'lucide-react';
import clsx from 'clsx';

const ExplanationCard = ({ humanExplanations }) => {
  if (!humanExplanations || humanExplanations.length === 0) return null;

  return (
    <div className="glass-panel p-8 space-y-6 hover:border-gray-700 transition-all duration-300 border-2 border-purple-500/20">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-purple-500/20 border border-purple-500/40">
            <Brain className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <h3 className="text-sm font-extrabold uppercase tracking-wider text-white">
              AI Analysis Breakdown
            </h3>
            <p className="text-xs text-gray-400 font-mono mt-0.5">Feature-level threat assessment</p>
          </div>
        </div>
      </div>

      <div className="space-y-3 max-h-[500px] overflow-y-auto pr-2">
        {humanExplanations.map((exp, idx) => {
          const isRisk = exp.impact_type === 'RISK_FACTOR';
          const impactValue = parseFloat(exp.impact_percent?.replace('%', '') || 0);
          
          return (
            <div 
              key={idx} 
              className={clsx(
                "group p-4 rounded-lg border-2 transition-all duration-300 cursor-default hover:shadow-lg relative overflow-hidden",
                isRisk 
                  ? "bg-danger/10 border-danger/20 hover:border-danger/40 hover:bg-danger/15" 
                  : "bg-safe/10 border-safe/20 hover:border-safe/40 hover:bg-safe/15"
              )}
            >
              {/* Animated background */}
              <div className={clsx(
                "absolute inset-0 opacity-0 group-hover:opacity-5 transition-opacity",
                isRisk ? "bg-danger" : "bg-safe"
              )} />

              <div className="relative z-10 flex items-start space-x-4">
                {/* Icon */}
                <div className="flex-shrink-0 mt-0.5">
                  {isRisk ? (
                    <div className="p-2 rounded bg-danger/20 border border-danger/30">
                      <ShieldAlert className="w-4 h-4 text-danger" />
                    </div>
                  ) : (
                    <div className="p-2 rounded bg-safe/20 border border-safe/30">
                      <Shield className="w-4 h-4 text-safe" />
                    </div>
                  )}
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="text-xs font-mono font-bold uppercase tracking-wider text-gray-300 truncate">
                      {exp.feature}
                    </span>
                    <div className="flex items-center space-x-1.5">
                      <span className={clsx(
                        "px-2.5 py-1 rounded-full text-xs font-black font-mono",
                        isRisk 
                          ? "bg-danger/20 text-danger border border-danger/40" 
                          : "bg-safe/20 text-safe border border-safe/40"
                      )}>
                        {exp.impact_percent}
                      </span>
                      <ChevronRight className={clsx("w-4 h-4 transition-transform group-hover:translate-x-1", isRisk ? "text-danger" : "text-safe")} />
                    </div>
                  </div>
                  <p className="text-sm text-gray-200 leading-relaxed font-sans">
                    {exp.message}
                  </p>
                  
                  {/* Impact bar */}
                  <div className="mt-2.5 flex items-center space-x-2">
                    <div className="flex-1 bg-gray-900/50 rounded-full h-1.5 overflow-hidden border border-gray-800">
                      <div 
                        className={clsx(
                          "h-full rounded-full transition-all",
                          isRisk ? "bg-danger" : "bg-safe"
                        )}
                        style={{ width: `${Math.min(Math.abs(impactValue), 100)}%` }}
                      />
                    </div>
                    <span className="text-[10px] font-mono text-gray-400 w-6 text-right">
                      {impactValue > 0 ? '+' : ''}{impactValue}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Footer explanation note */}
      <div className="flex items-start space-x-2 p-3 rounded-lg bg-purple-500/5 border border-purple-500/20">
        <Sparkles className="w-4 h-4 text-purple-400 flex-shrink-0 mt-0.5" />
        <span className="text-xs text-gray-300 font-mono leading-relaxed">
          <span className="text-purple-300 font-semibold">Positive values (+)</span> increase phishing likelihood. <span className="text-green-300 font-semibold">Negative values (-)</span> increase safety confidence.
        </span>
      </div>
    </div>
  );
};

export default ExplanationCard;
