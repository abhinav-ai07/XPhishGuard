import React, { useState, useEffect } from 'react';
import { ShieldAlert, Cpu, Zap, Radar } from 'lucide-react';

const Header = () => {
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const t = setInterval(() => setTick(p => p + 1), 1200);
    return () => clearInterval(t);
  }, []);

  const dots = ['●', '◐', '○'];

  return (
    <header className="border-b border-gray-800/50 bg-gradient-to-b from-surface/80 to-surface/40 backdrop-blur-xl sticky top-0 z-50 relative overflow-hidden">
      {/* Animated background grid */}
      <div className="absolute inset-0 opacity-10 pointer-events-none" style={{ backgroundImage: 'linear-gradient(0deg, transparent 24%, rgba(0, 255, 204, 0.05) 25%, rgba(0, 255, 204, 0.05) 26%, transparent 27%, transparent 74%, rgba(0, 255, 204, 0.05) 75%, rgba(0, 255, 204, 0.05) 76%, transparent 77%, transparent), linear-gradient(90deg, transparent 24%, rgba(0, 255, 204, 0.05) 25%, rgba(0, 255, 204, 0.05) 26%, transparent 27%, transparent 74%, rgba(0, 255, 204, 0.05) 75%, rgba(0, 255, 204, 0.05) 76%, transparent 77%, transparent)', backgroundSize: '60px 60px' }} />

      {/* Top accent bar */}
      <div className="h-[3px] w-full bg-gradient-to-r from-transparent via-brand via-cyan-400 to-transparent opacity-80 relative z-10" />

      <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between gap-6 relative z-10">
        {/* Logo & Branding */}
        <div className="flex items-center space-x-4">
          <div className="relative flex-shrink-0">
            <div className="absolute inset-0 bg-gradient-to-br from-brand to-cyan-400 blur-2xl opacity-20 rounded-full animate-pulse" />
            <div className="relative w-11 h-11 rounded-xl bg-gradient-to-br from-brand/30 to-cyan-400/10 border-2 border-brand/50 flex items-center justify-center shadow-lg shadow-brand/30">
              <ShieldAlert className="w-6 h-6 text-brand animate-pulse" />
            </div>
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-lg font-black tracking-widest text-white font-mono uppercase leading-none">
                XPhishGuard
              </h1>
              <span className="text-brand font-bold text-sm tracking-wider">AI</span>
              <span className="text-[10px] font-mono bg-brand/20 text-brand px-2 py-1 rounded-full border border-brand/40 tracking-widest uppercase font-bold">BETA</span>
            </div>
            <p className="text-[9px] text-gray-400 tracking-widest font-mono uppercase leading-none mt-1">
              Real-time Threat Detection Engine
            </p>
          </div>
        </div>

        {/* Status Indicators */}
        <div className="hidden lg:flex items-center gap-4">
          {[
            { icon: Cpu, label: 'AI ENGINE', value: 'ONLINE', color: 'from-brand to-cyan-400' },
            { icon: Radar, label: 'DETECTION', value: 'READY', color: 'from-purple-500 to-pink-500' },
            { icon: Zap, label: 'RESPONSE', value: 'INSTANT', color: 'from-amber-500 to-orange-500' },
          ].map(({ icon: Icon, label, value, color }, idx) => (
            <div key={idx} className={`relative group`}>
              <div className={`absolute -inset-1 bg-gradient-to-r ${color} blur-md opacity-0 group-hover:opacity-20 transition-opacity rounded-lg`} />
              <div className="relative flex items-center space-x-2.5 bg-gray-900/50 backdrop-blur-sm px-3 py-2 rounded-lg border border-gray-800 hover:border-gray-700 transition-all">
                <Icon className="w-3.5 h-3.5 text-gray-400" />
                <div className="leading-none">
                  <div className="text-[8px] text-gray-500 font-mono tracking-widest uppercase font-bold">{label}</div>
                  <div className={`text-xs font-black font-mono bg-gradient-to-r ${color} bg-clip-text text-transparent flex items-center gap-1`}>
                    <span className={`w-1.5 h-1.5 rounded-full bg-gradient-to-r ${color} animate-pulse inline-block`} />
                    {value}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Live time indicator */}
        <div className="hidden sm:block font-mono text-[9px] text-gray-500 tabular-nums bg-gray-900/30 px-3 py-1.5 rounded-lg border border-gray-800 backdrop-blur-sm">
          <span className="text-gray-400">{new Date().toISOString().replace('T', ' ').slice(0, 19)}</span>
          <span className="ml-1 text-brand font-bold animate-pulse">{dots[tick % 3]}</span>
        </div>
      </div>
    </header>
  );
};

export default Header;
