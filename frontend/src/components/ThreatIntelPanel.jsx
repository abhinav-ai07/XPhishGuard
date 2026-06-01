import React from 'react';
import { Database, CheckCircle2, XCircle, AlertTriangle } from 'lucide-react';
import clsx from 'clsx';

const ThreatIntelPanel = ({ result }) => {
  if (!result || !result.threat_intelligence) return null;

  const { threat_intelligence } = result;
  const { virustotal = {}, phishtank = false, openphish = false, urlhaus = false } = threat_intelligence;
  
  const vtDetections = virustotal.detections || 0;
  const isMaliciousInFeeds = vtDetections > 0 || phishtank || openphish || urlhaus;

  const feeds = [
    {
      name: 'VirusTotal Intelligence',
      status: vtDetections > 0,
      details: vtDetections > 0 ? `${vtDetections} engines flagged` : 'Clean Scan',
      isVT: true
    },
    {
      name: 'PhishTank Blacklist',
      status: phishtank,
      details: phishtank ? 'Match Found (Verified Phish)' : 'Not Listed'
    },
    {
      name: 'OpenPhish Active Feed',
      status: openphish,
      details: openphish ? 'Active URL Hit' : 'Not Listed'
    },
    {
      name: 'URLHaus Malware Feed',
      status: urlhaus,
      details: urlhaus ? 'Malware Domain Match' : 'Not Listed'
    }
  ];

  return (
    <div className={clsx(
      "glass-panel p-6 space-y-4 hover:border-gray-700 transition-all duration-300 relative overflow-hidden",
      isMaliciousInFeeds ? "border-danger/20 glow-danger" : "border-safe/10"
    )}>
      {/* Accent Background Glow */}
      <div className={clsx(
        "absolute -right-8 -top-8 w-24 h-24 rounded-full blur-2xl opacity-15 pointer-events-none",
        isMaliciousInFeeds ? "bg-danger" : "bg-safe"
      )} />

      <div className="flex items-center justify-between border-b border-gray-800 pb-3">
        <div className="flex items-center space-x-2">
          <Database className="w-5 h-5 text-brand" />
          <h3 className="text-sm font-extrabold uppercase tracking-wider text-gray-400">
            Real-time Threat Intelligence
          </h3>
        </div>
        <span className={clsx(
          "px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase",
          isMaliciousInFeeds ? "bg-danger/10 text-danger border border-danger/25 animate-pulse" : "bg-safe/10 text-safe border border-safe/25"
        )}>
          {isMaliciousInFeeds ? "INDICATORS FLAGGED" : "THREAT FEEDS CLEAN"}
        </span>
      </div>

      <div className="grid grid-cols-1 gap-3">
        {feeds.map((feed, idx) => (
          <div 
            key={idx} 
            className={clsx(
              "flex items-center justify-between p-3 rounded-lg border font-mono text-xs transition-colors",
              feed.status 
                ? "bg-danger/5 border-danger/10 text-danger" 
                : "bg-surfaceHighlight/20 border-gray-800/60 text-gray-400"
            )}
          >
            <div className="flex items-center space-x-3">
              {feed.status ? (
                <AlertTriangle className="w-4.5 h-4.5 text-danger flex-shrink-0 animate-bounce" />
              ) : (
                <CheckCircle2 className="w-4.5 h-4.5 text-safe flex-shrink-0" />
              )}
              <span className={clsx("font-bold", feed.status ? "text-danger" : "text-gray-300")}>
                {feed.name}
              </span>
            </div>
            <div className="text-right">
              <span className={clsx(
                "px-2 py-0.5 rounded text-[10px] font-bold uppercase",
                feed.status ? "bg-danger/20 text-danger border border-danger/30" : "bg-gray-800/40 text-gray-500"
              )}>
                {feed.details}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ThreatIntelPanel;
