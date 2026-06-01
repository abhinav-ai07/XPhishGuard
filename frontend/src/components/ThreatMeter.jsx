import React from 'react';
import clsx from 'clsx';
import { Activity, Gauge } from 'lucide-react';

const ThreatMeter = ({ confidence, riskLevel }) => {
  // confidence is a float 0.0 to 1.0
  const percentage = Math.round(confidence * 100);
  
  let colorClass = 'from-safe to-green-400';
  let glowClass = 'glow-safe';
  let textColor = 'text-safe';
  let statusText = 'SAFE';
  
  if (riskLevel === 'HIGH') {
    colorClass = 'from-danger to-red-500';
    glowClass = 'glow-danger';
    textColor = 'text-danger';
    statusText = 'CRITICAL';
  } else if (riskLevel === 'MEDIUM') {
    colorClass = 'from-amber-500 to-orange-500';
    glowClass = 'shadow-[0_0_20px_rgba(245,158,11,0.4)]';
    textColor = 'text-amber-400';
    statusText = 'WARNING';
  }

  return (
    <div className={clsx(
      "glass-panel p-6 w-full border-2 relative overflow-hidden",
      riskLevel === 'HIGH' ? 'border-danger/30 bg-danger/5' : riskLevel === 'MEDIUM' ? 'border-amber-500/30 bg-amber-500/5' : 'border-safe/30 bg-safe/5'
    )}>
      {/* Background glow */}
      <div className={clsx(
        "absolute -right-8 -top-8 w-24 h-24 rounded-full blur-2xl opacity-20 pointer-events-none",
        riskLevel === 'HIGH' ? "bg-danger" : riskLevel === 'MEDIUM' ? "bg-amber-500" : "bg-safe"
      )} />

      <div className="relative z-10">
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center space-x-2.5">
            <div className={clsx("p-2 rounded-lg", riskLevel === 'HIGH' ? 'bg-danger/20' : riskLevel === 'MEDIUM' ? 'bg-amber-500/20' : 'bg-safe/20')}>
              <Gauge className={clsx("w-5 h-5", textColor)} />
            </div>
            <h3 className="text-sm font-extrabold tracking-widest text-gray-200 uppercase font-mono">Threat Score</h3>
          </div>
          <div className="text-right">
            <div className={clsx("font-mono font-black text-4xl leading-none", textColor)}>
              {percentage}
              <span className="text-sm text-gray-400 ml-1">%</span>
            </div>
            <p className={clsx("text-xs font-bold tracking-widest mt-1", textColor)}>
              {statusText}
            </p>
          </div>
        </div>
        
        {/* Main confidence bar */}
        <div className="relative h-3 bg-gray-900/60 rounded-full overflow-hidden border border-gray-800/50 shadow-inner">
          {/* Background track */}
          <div className="absolute inset-0 bg-gradient-to-r from-gray-800/20 to-transparent rounded-full" />
          
          {/* Filled progress */}
          <div 
            className={clsx(
              "h-full rounded-full transition-all duration-1000 ease-out relative bg-gradient-to-r shadow-lg",
              colorClass,
              glowClass
            )}
            style={{ width: `${percentage}%` }}
          >
            {/* Animated shine effect */}
            <div className="absolute inset-0 bg-gradient-to-r from-white/30 via-white/10 to-transparent animate-[shimmer_2s_ease-in-out_infinite]"></div>
            
            {/* Moving light */}
            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/40 to-transparent w-1/4 animate-[slide_2s_ease-in-out_infinite]"></div>
          </div>
        </div>
        
        {/* Labels */}
        <div className="mt-4 grid grid-cols-3 gap-2 text-center">
          <div>
            <span className="text-[9px] font-mono text-gray-500 uppercase tracking-wider block mb-1">Low</span>
            <div className="h-1 rounded-full bg-safe/30 mx-auto w-8" />
          </div>
          <div>
            <span className="text-[9px] font-mono text-gray-500 uppercase tracking-wider block mb-1">Medium</span>
            <div className="h-1 rounded-full bg-amber-500/30 mx-auto w-8" />
          </div>
          <div>
            <span className="text-[9px] font-mono text-gray-500 uppercase tracking-wider block mb-1">High</span>
            <div className="h-1 rounded-full bg-danger/30 mx-auto w-8" />
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThreatMeter;
