import React from 'react';
import { ShieldCheck, ShieldAlert, Link as LinkIcon, Info } from 'lucide-react';
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
        
        <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div className="flex-1">
            <div className="flex items-center space-x-3 mb-2">
              {isSafe ? (
                <ShieldCheck className="w-8 h-8 text-safe" />
              ) : (
                <ShieldAlert className="w-8 h-8 text-danger animate-pulse" />
              )}
              <h2 className={clsx("text-4xl font-extrabold tracking-tight uppercase", statusColor)}>
                {isSafe ? 'SAFE' : 'PHISHING DETECTED'}
              </h2>
            </div>
            
            <div className="flex items-center space-x-2 text-gray-400 mt-4 bg-surfaceHighlight/50 p-3 rounded-lg border border-gray-800">
              <LinkIcon className="w-4 h-4 flex-shrink-0" />
              <span className="truncate font-mono text-sm">{url}</span>
            </div>
          </div>

          <div className="w-full md:w-1/3 min-w-[250px]">
            <ThreatMeter confidence={confidence_score} riskLevel={risk_level} />
          </div>
        </div>

        {/* Signals Section */}
        {triggered_signals && triggered_signals.length > 0 && (
          <div className="mt-6 pt-6 border-t border-gray-800/50">
            <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center">
              <Info className="w-4 h-4 mr-2" />
              Intelligence Triggers
            </h3>
            <div className="flex flex-wrap gap-2">
              {triggered_signals.map((signal, idx) => (
                <span 
                  key={idx} 
                  className={clsx(
                    "px-3 py-1.5 rounded-md text-xs font-bold uppercase tracking-wider border",
                    isSafe 
                      ? "bg-safe/20 text-safe border-safe/30" 
                      : "bg-danger/20 text-danger border-danger/30"
                  )}
                >
                  {signal}
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
