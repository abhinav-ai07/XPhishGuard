import React, { useState, useRef } from 'react';
import { Search, ShieldCheck, Zap, Lock, Globe, ArrowRight } from 'lucide-react';
import clsx from 'clsx';

const EXAMPLE_URLS = [
  'https://youtube-security-alert.xyz',
  'https://netfliix-login-auth.net',
  'https://paypal-verification-secure-login.com',
  'https://youtube.com',
];

const UrlForm = ({ onScan, isLoading }) => {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const [focused, setFocused] = useState(false);
  const inputRef = useRef(null);

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');
    const trimmed = url.trim();
    if (!trimmed) { setError('Enter a target URL to begin analysis.'); return; }
    let formatted = trimmed;
    if (!/^https?:\/\//i.test(trimmed)) formatted = 'http://' + trimmed;
    try { new URL(formatted); onScan(formatted); }
    catch { setError('Invalid URL format. Please check and retry.'); }
  };

  const loadExample = (u) => { setUrl(u); setError(''); inputRef.current?.focus(); };

  return (
    <div className="w-full max-w-5xl mx-auto">
      {/* Hero section */}
      <div className="text-center mb-10 space-y-4">
        <div className="inline-flex items-center space-x-2 bg-gradient-to-r from-brand/10 to-cyan-400/10 border border-brand/30 px-4 py-2 rounded-full mb-3 shadow-lg shadow-brand/5">
          <div className="w-2 h-2 rounded-full bg-brand animate-pulse" />
          <span className="text-xs font-mono font-bold text-brand tracking-widest uppercase">Advanced Threat Detection</span>
        </div>
        <h2 className="text-4xl sm:text-5xl font-black text-white tracking-tight leading-tight">
          Scan URLs for{' '}
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-brand to-blue-500">
            phishing threats
          </span>
        </h2>
        <p className="text-gray-400 text-base font-mono max-w-2xl mx-auto leading-relaxed">
          AI-powered analysis powered by 29-feature ML models, SHAP explainability, & live threat intelligence feeds
        </p>
      </div>

      {/* Scanner form */}
      <div className={clsx(
        'relative rounded-2xl border-2 transition-all duration-300 overflow-hidden',
        focused ? 'border-cyan-400/50 shadow-[0_0_50px_rgba(34,211,238,0.2)]' : 'border-gray-800/50',
        'bg-gradient-to-b from-gray-900/80 to-gray-950/60 backdrop-blur-xl'
      )}>
        {/* Gradient top border */}
        <div className={clsx(
          'h-[2px] w-full transition-all duration-500',
          focused ? 'bg-gradient-to-r from-transparent via-cyan-400 to-transparent' : 'bg-gray-800/30'
        )} />

        <form onSubmit={handleSubmit} className="p-6 sm:p-8">
          <div className="flex flex-col sm:flex-row gap-4">
            {/* Input */}
            <div className="relative flex-grow group">
              <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                <Globe className={clsx('h-5 w-5 transition-colors duration-300', focused ? 'text-cyan-400' : 'text-gray-600')} />
              </div>
              <input
                ref={inputRef}
                type="text"
                className={clsx(
                  'block w-full pl-12 pr-4 py-3.5 bg-gray-950/50 border rounded-xl text-gray-100 focus:outline-none transition-all font-mono text-sm placeholder:text-gray-700 shadow-inner',
                  error
                    ? 'border-red-500/50 focus:border-red-500 focus:ring-2 focus:ring-red-500/20'
                    : focused
                    ? 'border-cyan-400/50 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-400/20 shadow-lg shadow-cyan-400/5'
                    : 'border-gray-800/70'
                )}
                placeholder="https://example-url-to-analyze.com"
                value={url}
                onChange={e => setUrl(e.target.value)}
                onFocus={() => setFocused(true)}
                onBlur={() => setFocused(false)}
                disabled={isLoading}
                autoComplete="off"
                spellCheck="false"
              />
              {url && (
                <div className="absolute inset-y-0 right-4 flex items-center">
                  <div className="flex items-center space-x-1">
                    {url.startsWith('https') ? (
                      <ShieldCheck className="w-4 h-4 text-safe animate-pulse" />
                    ) : (
                      <Lock className="w-4 h-4 text-amber-500/70" />
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Button */}
            <button
              type="submit"
              disabled={isLoading}
              className={clsx(
                'flex items-center justify-center space-x-2.5 px-8 py-3.5 rounded-xl font-bold font-mono text-sm tracking-wider transition-all duration-300 min-w-[160px] group relative overflow-hidden',
                'disabled:opacity-50 disabled:cursor-not-allowed',
                isLoading
                  ? 'bg-gradient-to-r from-brand/30 to-cyan-400/30 text-cyan-300 border border-brand/30'
                  : 'bg-gradient-to-r from-cyan-500 to-brand text-white hover:from-cyan-400 hover:to-brand/90 shadow-lg shadow-cyan-500/40 hover:shadow-cyan-500/60 active:scale-[0.97] border border-cyan-400/50 hover:border-cyan-400'
              )}
            >
              {isLoading ? (
                <>
                  <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  <span>SCANNING…</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4 group-hover:scale-110 transition-transform" />
                  <span>SCAN</span>
                  <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
                </>
              )}
            </button>
          </div>

          {/* Error */}
          {error && (
            <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center space-x-2">
              <span className="text-red-400 font-bold">⚠</span>
              <p className="text-xs text-red-300 font-mono">{error}</p>
            </div>
          )}
        </form>

        {/* Example URLs strip */}
        <div className="px-6 sm:px-8 pb-6 border-t border-gray-800/30">
          <div className="flex flex-col sm:flex-row gap-3 items-start sm:items-center flex-wrap">
            <span className="text-[10px] text-gray-500 font-mono uppercase tracking-widest font-bold flex items-center space-x-1">
              <Zap className="w-3 h-3" />
              <span>Quick test:</span>
            </span>
            {EXAMPLE_URLS.map(u => (
              <button
                key={u}
                onClick={() => loadExample(u)}
                disabled={isLoading}
                className="text-[10px] font-mono text-gray-400 hover:text-cyan-300 bg-gray-900/40 hover:bg-cyan-500/10 border border-gray-800/50 hover:border-cyan-500/40 px-3 py-1.5 rounded-lg transition-all duration-300 truncate max-w-[220px] hover:shadow-lg hover:shadow-cyan-500/10 hover:scale-105"
                title={u}
              >
                {u.replace('https://', '').replace('http://', '').slice(0, 32)}
                {u.length > 40 ? '…' : ''}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default UrlForm;
