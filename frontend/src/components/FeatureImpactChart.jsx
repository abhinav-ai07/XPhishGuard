import React, { useState } from 'react';
import { BarChart2, TrendingUp, Compass, Maximize2, Download, Zap } from 'lucide-react';
import clsx from 'clsx';

const FeatureImpactChart = ({ visualizations }) => {
  if (!visualizations) return null;

  const [activeTab, setActiveTab] = useState('local_importance');

  const tabs = [
    { id: 'local_importance', label: 'Feature Impact', icon: BarChart2, desc: 'Local feature contributions combining Machine Learning weights and hybrid heuristics.' },
    { id: 'waterfall', label: 'SHAP Waterfall Plot', icon: TrendingUp, desc: 'SHAP Waterfall plot mapping features from their base log-odds value to the model prediction.' },
    { id: 'force', label: 'SHAP Force Plot', icon: Compass, desc: 'SHAP Force plot showing the pushing forces of risk increase vs risk decrease features.' },
  ];

  const activeVisual = visualizations[activeTab];

  const handleDownload = () => {
    if (!activeVisual) return;
    const link = document.createElement('a');
    link.href = `data:image/png;base64,${activeVisual}`;
    link.download = `xphishguard_${activeTab}.png`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="glass-panel p-8 space-y-6 hover:border-gray-700 transition-all duration-300 border-2 border-cyan-500/20">
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-6">
        <div className="flex items-start space-x-4">
          <div className="p-2.5 rounded-lg bg-cyan-500/20 border border-cyan-500/40">
            <BarChart2 className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h3 className="text-sm font-extrabold uppercase tracking-wider text-white">
              Explainable AI Visualization Suite
            </h3>
            <p className="text-xs text-gray-400 font-mono mt-1">
              Game-theoretic Shapley values & interpretable ML analysis
            </p>
          </div>
        </div>
        
        {/* Tab Switcher */}
        <div className="flex flex-wrap gap-1 bg-gray-900/40 p-1.5 rounded-lg border border-gray-800 backdrop-blur-sm">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  "flex items-center space-x-2 px-3 py-2 rounded-md text-xs font-semibold transition-all duration-300 group relative",
                  isActive
                    ? "bg-gradient-to-r from-cyan-500 to-blue-500 text-white shadow-lg shadow-cyan-500/20 font-bold"
                    : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/40 border border-transparent hover:border-gray-700"
                )}
              >
                <Icon className="w-4 h-4" />
                <span>{tab.label}</span>
                {isActive && <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-400 to-blue-400" />}
              </button>
            );
          })}
        </div>
      </div>

      {/* Active Tab Description & Download */}
      <div className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 p-4 rounded-lg border border-cyan-500/30 flex items-center justify-between">
        <div className="flex items-center space-x-2 flex-1">
          <Zap className="w-4 h-4 text-cyan-400 flex-shrink-0" />
          <p className="text-xs font-mono text-gray-300">
            {tabs.find(t => t.id === activeTab)?.desc}
          </p>
        </div>
        {activeVisual && (
          <button 
            onClick={handleDownload}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-gradient-to-r from-cyan-500/20 to-blue-500/20 hover:from-cyan-500/40 hover:to-blue-500/40 text-xs font-mono font-semibold text-cyan-300 border border-cyan-500/40 hover:border-cyan-500/60 transition-all shadow-lg shadow-cyan-500/10 hover:shadow-cyan-500/20 flex-shrink-0 ml-4"
            title="Download PNG Chart"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export</span>
          </button>
        )}
      </div>

      {/* Image Viewing Container */}
      <div className="flex justify-center items-center w-full min-h-[280px] bg-gradient-to-br from-gray-900/50 to-gray-950/50 rounded-lg border-2 border-gray-800/50 p-3 overflow-hidden relative group shadow-xl shadow-cyan-500/5">
        {activeVisual ? (
          <div className="relative max-w-full transform transition-transform duration-300 group-hover:scale-105">
            <img 
              src={`data:image/png;base64,${activeVisual}`} 
              alt={`SHAP plot ${activeTab}`} 
              className="max-h-[400px] object-contain rounded-lg transition-all duration-300 group-hover:opacity-95 shadow-xl shadow-black/30" 
            />
            {/* Hover overlay with zoom button */}
            <div className="absolute inset-0 bg-gradient-to-t from-black/40 to-transparent opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity pointer-events-none rounded-lg">
              <button 
                onClick={() => {
                  const w = window.open();
                  w.document.write(`<iframe src="data:image/png;base64,${activeVisual}" frameborder="0" style="border:0; top:0px; left:0px; bottom:0px; right:0px; width:100%; height:100%;" allowfullscreen></iframe>`);
                }}
                className="bg-gradient-to-r from-cyan-500 to-blue-500 text-white px-4 py-2 rounded-lg border border-cyan-400 shadow-xl pointer-events-auto flex items-center space-x-2 text-xs font-mono font-bold transition-all hover:shadow-2xl hover:shadow-cyan-500/40"
              >
                <Maximize2 className="w-4 h-4" />
                <span>Open Full View</span>
              </button>
            </div>
          </div>
        ) : (
          <p className="text-xs font-mono text-gray-500 italic">No image generated for this metric.</p>
        )}
      </div>
    </div>
  );
};

export default FeatureImpactChart;
