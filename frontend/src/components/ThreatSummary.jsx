import React from 'react';
import { AlertTriangle, ShieldCheck, ShieldAlert, Zap, TrendingUp, Clock } from 'lucide-react';
import clsx from 'clsx';

const ThreatSummary = ({ result }) => {
  if (!result) return null;

  const { is_phishing, confidence_score, risk_level, analyst_summary } = result;
  const isSafe = !is_phishing;
  const scorePercent = (confidence_score * 100).toFixed(1);

  return (
    <div className="glass-panel p-8 space-y-6 relative overflow-hidden transition-all duration-300 hover:border-gray-700 border-2 border-brand/20">
      {/* Background accent glow */}
      <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-brand/10 to-transparent rounded-bl-full pointer-events-none" />
      <div className="absolute -left-16 -bottom-16 w-40 h-40 bg-gradient-to-tr from-brand/5 to-transparent rounded-tr-full pointer-events-none" />

      <div className="relative z-10">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-brand/20 border border-brand/40">
              <Zap className="w-5 h-5 text-brand" />
            </div>
            <div>
              <h3 className="text-sm font-extrabold uppercase tracking-wider text-white">
                THREAT INTELLIGENCE REPORT
              </h3>
              <p className="text-xs text-gray-400 font-mono mt-0.5">AI Classification & Risk Assessment</p>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Status Card */}
          <div className="group relative overflow-hidden">
            <div className={clsx(
              "p-5 rounded-lg border-2 backdrop-blur-sm transition-all duration-300 cursor-default hover:shadow-lg",
              isSafe 
                ? "bg-safe/10 border-safe/30 hover:border-safe/50 hover:bg-safe/15" 
                : "bg-danger/10 border-danger/30 hover:border-danger/50 hover:bg-danger/15"
            )}>
              <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
              <div className="relative z-10">
                <div className="text-xs font-mono text-gray-400 uppercase tracking-widest mb-2 flex items-center space-x-1">
                  <Clock className="w-3 h-3" />
                  <span>Status</span>
                </div>
                <div className="flex items-center space-x-2">
                  {isSafe ? (
                    <ShieldCheck className="w-6 h-6 text-safe" />
                  ) : (
                    <ShieldAlert className="w-6 h-6 text-danger animate-pulse" />
                  )}
                  <span className={clsx("text-2xl font-black tracking-tight", isSafe ? "text-safe" : "text-danger")}>
                    {isSafe ? "SAFE" : "THREAT"}
                  </span>
                </div>
                <p className={clsx("text-[10px] font-mono mt-2 uppercase tracking-wider", isSafe ? "text-safe/60" : "text-danger/60")}>
                  {isSafe ? "No phishing detected" : "Phishing confirmed"}
                </p>
              </div>
            </div>
          </div>

          {/* Confidence Card */}
          <div className="group relative overflow-hidden">
            <div className="p-5 rounded-lg border-2 bg-amber-500/10 border-amber-500/30 backdrop-blur-sm transition-all duration-300 cursor-default hover:shadow-lg hover:border-amber-500/50 hover:bg-amber-500/15">
              <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
              <div className="relative z-10">
                <div className="text-xs font-mono text-gray-400 uppercase tracking-widest mb-2 flex items-center space-x-1">
                  <TrendingUp className="w-3 h-3" />
                  <span>Confidence</span>
                </div>
                <div className="flex items-baseline space-x-1">
                  <span className="text-3xl font-black text-amber-400">{scorePercent}</span>
                  <span className="text-xs text-amber-300 font-mono">%</span>
                </div>
                {/* Confidence Bar */}
                <div className="w-full bg-gray-900/50 rounded-full h-2 overflow-hidden mt-3 border border-gray-800">
                  <div 
                    className="h-full bg-gradient-to-r from-amber-500 to-amber-400 rounded-full transition-all duration-1000 shadow-lg shadow-amber-500/40"
                    style={{ width: `${scorePercent}%` }}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Risk Level Card */}
          <div className="group relative overflow-hidden">
            <div className={clsx(
              "p-5 rounded-lg border-2 backdrop-blur-sm transition-all duration-300 cursor-default hover:shadow-lg",
              risk_level === 'HIGH' ? "bg-danger/10 border-danger/30 hover:border-danger/50 hover:bg-danger/15" :
              risk_level === 'MEDIUM' ? "bg-amber-500/10 border-amber-500/30 hover:border-amber-500/50 hover:bg-amber-500/15" :
              "bg-safe/10 border-safe/30 hover:border-safe/50 hover:bg-safe/15"
            )}>
              <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
              <div className="relative z-10">
                <div className="text-xs font-mono text-gray-400 uppercase tracking-widest mb-2 flex items-center space-x-1">
                  <AlertTriangle className="w-3 h-3" />
                  <span>Risk Level</span>
                </div>
                <div className={clsx(
                  "text-2xl font-black tracking-tight",
                  risk_level === 'HIGH' ? "text-danger" :
                  risk_level === 'MEDIUM' ? "text-amber-400" :
                  "text-safe"
                )}>
                  {risk_level}
                </div>
                <div className="w-full flex space-x-1 mt-3">
                  {[1, 2, 3].map((i) => (
                    <div 
                      key={i}
                      className={clsx(
                        "flex-1 h-1 rounded-full transition-all",
                        (risk_level === 'HIGH' && i <= 3) ||
                        (risk_level === 'MEDIUM' && i <= 2) ||
                        (risk_level === 'LOW' && i <= 1)
                          ? risk_level === 'HIGH' ? "bg-danger" : risk_level === 'MEDIUM' ? "bg-amber-400" : "bg-safe"
                          : "bg-gray-800"
                      )}
                    />
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="mt-6 p-5 rounded-lg border border-brand/30 bg-brand/5 backdrop-blur-sm">
          <p className="text-xs font-mono text-gray-400 uppercase tracking-widest mb-2 block">Executive Summary</p>
          <p className="text-sm text-gray-200 leading-relaxed font-sans">
            {analyst_summary}
          </p>
        </div>
      </div>
    </div>
  );
};

export default ThreatSummary;
