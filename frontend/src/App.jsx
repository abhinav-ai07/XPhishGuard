import React, { useState } from 'react';
import Header from './components/Header';
import UrlForm from './components/UrlForm';
import ResultCard from './components/ResultCard';
import FeatureTable from './components/FeatureTable';
import Loader from './components/Loader';
import { scanUrl } from './services/api';

function App() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleScan = async (url) => {
    setLoading(true);
    setResult(null);
    setError(null);
    
    try {
      const data = await scanUrl(url);
      setResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-background selection:bg-brand/30">
      {/* Dynamic Background Pattern */}
      <div className="fixed inset-0 z-0 opacity-20 pointer-events-none" style={{ backgroundImage: 'radial-gradient(#333 1px, transparent 1px)', backgroundSize: '40px 40px' }}></div>
      
      <Header />
      
      <main className="flex-grow flex flex-col items-center justify-start pt-12 pb-24 px-4 sm:px-6 lg:px-8 z-10 w-full max-w-6xl mx-auto space-y-8">
        
        <UrlForm onScan={handleScan} isLoading={loading} />

        {error && (
          <div className="w-full max-w-4xl bg-danger/10 border border-danger/50 p-4 rounded-lg flex items-center justify-center animate-fade-in-up">
            <p className="text-danger font-mono text-sm font-bold">ERROR: {error}</p>
          </div>
        )}

        {loading && <Loader />}

        {result && !loading && (
          <div className="w-full max-w-4xl space-y-6 animate-fade-in-up">
            <ResultCard result={result} />
            <FeatureTable features={result.features} />
          </div>
        )}

      </main>

      <footer className="py-6 border-t border-gray-800 text-center text-sm text-gray-500 font-mono z-10 bg-surface/80 backdrop-blur-sm">
        XPhishGuard AI — Advanced Hybrid Cybersecurity Engine
      </footer>
    </div>
  );
}

export default App;
