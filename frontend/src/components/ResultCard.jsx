import React from 'react';
import { ShieldCheck, ShieldAlert, Link as LinkIcon, Info, Zap, Activity } from 'lucide-react';
import clsx from 'clsx';
import ThreatMeter from './ThreatMeter';

const ResultCard = ({ result }) => {
  if (!result) return null;

  const { is_phishing, confidence_score, risk_level, triggered_signals, url } = result;

  const isSafe = !is_phishing;
  const statusColor = isSafe ? 'text-safe' : 'text-danger';
  const statusBg = isSafe ? 'bg-safe/10 border-safe/30' : 'bg-danger/10 border-danger/30';
  const statusGlow = isSafe ? 'glow-safe' : 'glow-danger';

  return (
    <div className="w-full space-y-6 animate-fade-in-up">
      {/* Primary Verdict Card */}
      <div className={clsx("glass-panel p-8 border-2 relative overflow-hidden transition-all duration-500", statusBg, statusGlow)}>
        {/* Background emblem */}
        <div className="absolute -right-10 -bottom-10 opacity-5 pointer-events-none">
          {isSafe ? <ShieldCheck className="w-64 h-64" /> : <ShieldAlert className="w-64 h-64" />}
        </div>
        
        {/* Animated grid background */}
        <div className="absolute inset-0 opacity-5 pointer-events-none" style={{ 
          backgroundImage: 'linear-gradient(0deg, transparent 24%, rgba(68, 184, 107, .05) 25%, rgba(68, 184, 107, .05) 26%, transparent 27%, transparent 74%, rgba(68, 184, 107, .05) 75%, rgba(68, 184, 107, .05) 76%, transparent 77%, transparent), linear-gradient(90deg, transparent 24%, rgba(68, 184, 107, .05) 25%, rgba(68, 184, 107, .05) 26%, transparent 27%, transparent 74%, rgba(68, 184, 107, .05) 75%, rgba(68, 184, 107, .05) 76%, transparent 77%, transparent)',
          backgroundSize: '50px 50px'
        }}></div>
        
        <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-8">
          <div className="flex-1">
            <div className="flex items-center space-x-4 mb-4">
              <div className={clsx("p-3 rounded-lg border-2", isSafe ? "bg-safe/20 border-safe/50" : "bg-danger/20 border-danger/50")}>
                {isSafe ? (
                  <ShieldCheck className={clsx("w-8 h-8", statusColor)} />
                ) : (
                  <ShieldAlert className={clsx("w-8 h-8 animate-pulse", statusColor)} />
                )}
              </div>
              <div>
                <h2 className={clsx("text-5xl font-black tracking-tighter uppercase", statusColor)}>
                  {isSafe ? 'SECURE' : 'THREAT'}
                </h2>
                <p className="text-xs font-mono text-gray-400 mt-1 tracking-widest">ANALYSIS COMPLETE</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-2 text-gray-400 mt-6 bg-background/50 p-4 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors">
              <LinkIcon className="w-4 h-4 flex-shrink-0 text-gray-500" />
              <span className="truncate font-mono text-sm text-gray-300">{url}</span>
            </div>
          </div>

          <div className="w-full md:w-auto">
            <ThreatMeter confidence={confidence_score} riskLevel={risk_level} />
          </div>
        </div>

        {/* Signals Section */}
        {triggered_signals && triggered_signals.length > 0 && (
          <div className="mt-8 pt-6 border-t border-gray-800/50">
            <div className="flex items-center space-x-2 mb-4">
              <Activity className="w-4 h-4 text-brand" />
              <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider font-mono">
                Detection Signals ({triggered_signals.length})
              </h3>
            </div>
            <div className="flex flex-wrap gap-2">
              {triggered_signals.map((signal, idx) => (
                <span 
                  key={idx} 
                  className={clsx(
                    "px-4 py-2 rounded-full text-xs font-bold uppercase tracking-wider border backdrop-blur-sm transition-all hover:scale-105",
                    isSafe 
                      ? "bg-safe/15 text-safe border-safe/40 shadow-lg shadow-safe/5" 
                      : "bg-danger/15 text-danger border-danger/40 shadow-lg shadow-danger/5"
                  )}
                >
                  <span className="flex items-center space-x-1">
                    <Zap className="w-3 h-3" />
                    <span>{signal}</span>
                  </span>
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ResultCard;
