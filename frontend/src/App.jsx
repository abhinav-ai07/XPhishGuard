import React, { useState } from 'react';
import Header from './components/Header';
import UrlForm from './components/UrlForm';
import ResultCard from './components/ResultCard';
import Loader from './components/Loader';
import ThreatSummary from './components/ThreatSummary';
import FeatureImpactChart from './components/FeatureImpactChart';
import AnalystReport from './components/AnalystReport';
import ExplanationCard from './components/ExplanationCard';
import ModelAuditReport from './components/ModelAuditReport';
import { scanUrl } from './services/api';
import { Shield, Settings } from 'lucide-react';
import clsx from 'clsx';

function App() {
  const [activeSection, setActiveSection] = useState('scanner'); // scanner, audit
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
      
      {/* Section navigation tabs */}
      <div className="w-full max-w-6xl mx-auto px-4 pt-6 z-10">
        <div className="flex border-b border-gray-800">
          <button
            onClick={() => setActiveSection('scanner')}
            className={clsx(
              "flex items-center space-x-2 px-6 py-3 border-b-2 font-mono text-sm tracking-wider font-semibold transition-all duration-300",
              activeSection === 'scanner'
                ? "border-brand text-brand bg-brand/5 font-extrabold"
                : "border-transparent text-gray-500 hover:text-gray-300 hover:bg-gray-800/10"
            )}
          >
            <Shield className="w-4 h-4" />
            <span>URL TARGET SCANNER</span>
          </button>
          <button
            onClick={() => setActiveSection('audit')}
            className={clsx(
              "flex items-center space-x-2 px-6 py-3 border-b-2 font-mono text-sm tracking-wider font-semibold transition-all duration-300",
              activeSection === 'audit'
                ? "border-brand text-brand bg-brand/5 font-extrabold"
                : "border-transparent text-gray-500 hover:text-gray-300 hover:bg-gray-800/10"
            )}
          >
            <Settings className="w-4 h-4" />
            <span>XAI MODEL AUDITING & BIAS</span>
          </button>
        </div>
      </div>

      <main className="flex-grow flex flex-col items-center justify-start pt-6 pb-24 px-4 sm:px-6 lg:px-8 z-10 w-full max-w-6xl mx-auto space-y-8">
        
        {activeSection === 'scanner' ? (
          <>
            <UrlForm onScan={handleScan} isLoading={loading} />

            {error && (
              <div className="w-full max-w-5xl bg-danger/10 border border-danger/50 p-4 rounded-lg flex items-center justify-center animate-fade-in-up">
                <p className="text-danger font-mono text-sm font-bold">ERROR: {error}</p>
              </div>
            )}

            {loading && <Loader />}

            {result && !loading && (
              <div className="w-full max-w-5xl space-y-8 animate-fade-in-up">
                {/* 1. Verdict & Threat Score */}
                <ResultCard result={result} />

                {/* 2. Natural Language Threat Summary */}
                <ThreatSummary result={result} />

                {/* 3. Comprehensive Analysis: Explanations & Visualizations */}
                <div className="space-y-8">
                  <ExplanationCard humanExplanations={result.human_explanations} />
                  <FeatureImpactChart visualizations={result.visualizations} />
                </div>

                {/* 4. Structured SOC Analyst Report */}
                <AnalystReport result={result} />
              </div>
            )}
          </>
        ) : (
          <div className="w-full max-w-5xl space-y-6 animate-fade-in-up">
            <ModelAuditReport />
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
