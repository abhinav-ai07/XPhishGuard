import React, { useState } from 'react';
import { Search, Shield } from 'lucide-react';
import clsx from 'clsx';

const UrlForm = ({ onScan, isLoading }) => {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');

    const trimmed = url.trim();
    if (!trimmed) {
      setError('Please enter a URL');
      return;
    }
    
    // Basic formatting: if no http/https is provided, assume http
    let formattedUrl = trimmed;
    if (!/^https?:\/\//i.test(trimmed)) {
      formattedUrl = 'http://' + trimmed;
    }

    try {
      new URL(formattedUrl);
      onScan(formattedUrl);
    } catch (err) {
      setError('Please enter a valid URL');
    }
  };

  return (
    <div className="glass-panel p-6 sm:p-8 max-w-4xl mx-auto w-full relative overflow-hidden group">
      {/* Decorative gradient */}
      <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-brand/20 via-brand to-brand/20"></div>
      
      <div className="text-center mb-8">
        <h2 className="text-2xl font-bold text-white mb-2">Threat Intelligence Scanner</h2>
        <p className="text-gray-400 text-sm">Deploying 24-dimensional ML lexical analysis combined with trusted domain reputation.</p>
      </div>

      <form onSubmit={handleSubmit} className="relative z-10">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative flex-grow">
            <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
              <Search className="h-5 w-5 text-gray-500" />
            </div>
            <input
              type="text"
              className={clsx(
                "block w-full pl-12 pr-4 py-4 bg-surfaceHighlight border text-gray-100 rounded-lg focus:outline-none focus:ring-2 transition-all font-mono text-sm",
                error 
                  ? "border-danger focus:ring-danger/50" 
                  : "border-gray-700 focus:border-brand focus:ring-brand/30"
              )}
              placeholder="Enter URL to scan (e.g., netfliix-login.com)"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              disabled={isLoading}
            />
          </div>
          <button
            type="submit"
            disabled={isLoading}
            className="flex items-center justify-center space-x-2 bg-brand text-background hover:bg-brand/90 px-8 py-4 rounded-lg font-bold transition-all disabled:opacity-50 disabled:cursor-not-allowed min-w-[160px] shadow-[0_0_15px_rgba(0,255,204,0.3)] hover:shadow-[0_0_25px_rgba(0,255,204,0.5)]"
          >
            {isLoading ? (
              <>
                <svg className="animate-spin h-5 w-5 text-background" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <span>SCANNING</span>
              </>
            ) : (
              <>
                <Shield className="w-5 h-5" />
                <span>INITIATE SCAN</span>
              </>
            )}
          </button>
        </div>
        {error && (
          <p className="mt-3 text-sm text-danger flex items-center font-medium">
            <span className="mr-1">⚠</span> {error}
          </p>
        )}
      </form>
    </div>
  );
};

export default UrlForm;
