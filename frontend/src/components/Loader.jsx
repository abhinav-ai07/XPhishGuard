import React from 'react';

const Loader = () => {
  return (
    <div className="flex flex-col items-center justify-center py-12">
      <div className="relative">
        {/* Outer rotating ring */}
        <div className="w-24 h-24 rounded-full border-4 border-gray-800 border-t-brand animate-spin"></div>
        {/* Inner pulsing circle */}
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-16 h-16 bg-brand/20 rounded-full animate-pulse blur-md"></div>
        {/* Core dot */}
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-4 h-4 bg-brand rounded-full"></div>
      </div>
      <h3 className="mt-6 text-brand font-mono font-bold tracking-widest text-lg animate-pulse">ANALYZING THREAT VECTORS</h3>
      <p className="mt-2 text-gray-500 text-sm font-mono">Running hybrid ML reputation scoring...</p>
    </div>
  );
};

export default Loader;
