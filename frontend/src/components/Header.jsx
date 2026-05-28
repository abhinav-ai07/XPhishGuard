import React from 'react';
import { ShieldAlert } from 'lucide-react';

const Header = () => {
  return (
    <header className="border-b border-gray-800 bg-surface/50 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="relative">
            <ShieldAlert className="w-8 h-8 text-brand" />
            <div className="absolute inset-0 bg-brand blur-md opacity-30"></div>
          </div>
          <h1 className="text-xl font-bold tracking-wider text-white">
            XPHISHGUARD <span className="text-brand font-mono text-sm ml-1">AI</span>
          </h1>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-sm text-gray-400">
            <span className="w-2 h-2 rounded-full bg-safe animate-pulse"></span>
            <span>Hybrid Engine Active</span>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
