import React from 'react';
import clsx from 'clsx';
import { Activity } from 'lucide-react';

const ThreatMeter = ({ confidence, riskLevel }) => {
  // confidence is a float 0.0 to 1.0
  const percentage = Math.round(confidence * 100);
  
  let colorClass = 'bg-safe';
  let glowClass = 'glow-safe';
  
  if (riskLevel === 'HIGH') {
    colorClass = 'bg-danger';
    glowClass = 'glow-danger';
  } else if (riskLevel === 'MEDIUM') {
    colorClass = 'bg-yellow-500';
    glowClass = 'shadow-[0_0_15px_rgba(234,179,8,0.3)]';
  }

  return (
    <div className="glass-panel p-6 w-full">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          <Activity className="w-5 h-5 text-gray-400" />
          <h3 className="text-sm font-semibold tracking-wider text-gray-300 uppercase">Threat Confidence</h3>
        </div>
        <span className={clsx("font-mono font-bold text-2xl", 
          riskLevel === 'HIGH' ? 'text-danger' : riskLevel === 'MEDIUM' ? 'text-yellow-500' : 'text-safe'
        )}>
          {percentage}%
        </span>
      </div>
      
      <div className="h-4 bg-gray-800 rounded-full overflow-hidden relative">
        <div 
          className={clsx("h-full rounded-full transition-all duration-1000 ease-out relative", colorClass, glowClass)}
          style={{ width: `${percentage}%` }}
        >
          {/* Animated shine effect */}
          <div className="absolute inset-0 bg-white/20 w-full animate-[pulse_2s_ease-in-out_infinite]"></div>
        </div>
      </div>
      
      <div className="mt-3 flex justify-between text-xs font-mono text-gray-500">
        <span>0% (SAFE)</span>
        <span>50%</span>
        <span>100% (CRITICAL)</span>
      </div>
    </div>
  );
};

export default ThreatMeter;
