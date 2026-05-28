import React from 'react';
import { Database, AlertTriangle, ShieldCheck } from 'lucide-react';
import clsx from 'clsx';

const formatFeatureName = (name) => {
  return name.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
};

const FeatureTable = ({ features }) => {
  if (!features) return null;

  // Group features logically
  const riskFeatures = [
    'is_risky_tld', 'brand_impersonation', 'has_scam_keywords', 
    'is_shortened', 'has_redirect_params', 'is_ip_address'
  ];
  
  const trustFeatures = [
    'is_trusted_domain', 'is_institutional_tld', 'is_search_engine',
    'is_ai_platform', 'is_streaming_platform', 'is_coding_platform',
    'is_educational_platform', 'is_social_platform'
  ];

  const structuralFeatures = [
    'url_length', 'domain_entropy', 'subdomain_count', 'token_count',
    'dot_count', 'hyphen_count', 'digit_ratio', 'keyword_density'
  ];

  const renderRow = (key, val, type) => {
    // Treat 1 as true, 0 as false for boolean-like numerical features
    const isBool = val === 0 || val === 1;
    let displayVal = val;
    if (isBool) {
      displayVal = val === 1 ? 'Detected' : 'None';
    } else if (typeof val === 'number' && !Number.isInteger(val)) {
      displayVal = val.toFixed(3);
    }

    let highlightClass = 'text-gray-300';
    let Icon = Database;

    if (type === 'risk' && val === 1) {
      highlightClass = 'text-danger font-bold';
      Icon = AlertTriangle;
    } else if (type === 'trust' && val === 1) {
      highlightClass = 'text-safe font-bold';
      Icon = ShieldCheck;
    }

    return (
      <div key={key} className="flex justify-between items-center py-2 border-b border-gray-800/50 hover:bg-gray-800/20 px-2 rounded transition-colors">
        <div className="flex items-center space-x-2">
          <Icon className={clsx("w-4 h-4", val === 1 && type === 'risk' ? 'text-danger' : val === 1 && type === 'trust' ? 'text-safe' : 'text-gray-500')} />
          <span className="text-sm text-gray-400 font-medium">{formatFeatureName(key)}</span>
        </div>
        <span className={clsx("text-sm font-mono", highlightClass)}>
          {displayVal}
        </span>
      </div>
    );
  };

  return (
    <div className="glass-panel p-6 w-full">
      <h3 className="text-lg font-bold text-white mb-4 border-b border-gray-700 pb-2 flex items-center">
        <Database className="w-5 h-5 mr-2 text-brand" />
        Extracted ML Features
      </h3>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-x-12 gap-y-6">
        <div>
          <h4 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-3">Threat & Reputation Signals</h4>
          <div className="space-y-1">
            {riskFeatures.map(k => renderRow(k, features[k], 'risk'))}
            {trustFeatures.map(k => features[k] === 1 && renderRow(k, features[k], 'trust'))}
          </div>
        </div>
        
        <div>
          <h4 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-3">Structural & Lexical Metrics</h4>
          <div className="space-y-1">
            {structuralFeatures.map(k => renderRow(k, features[k], 'struct'))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default FeatureTable;
