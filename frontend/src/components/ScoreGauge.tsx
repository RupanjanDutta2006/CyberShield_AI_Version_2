import React from 'react';

interface ScoreGaugeProps {
  score: number;
  riskLevel?: string;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({ score }) => {
  const getColor = () => {
    if (score >= 80) return 'text-red-400 stroke-red-500';
    if (score >= 60) return 'text-orange-400 stroke-orange-500';
    if (score >= 35) return 'text-amber-400 stroke-amber-500';
    if (score > 0) return 'text-emerald-400 stroke-emerald-500';
    return 'text-slate-400 stroke-slate-500';
  };

  const getProgressColor = () => {
    if (score >= 80) return 'bg-red-500';
    if (score >= 60) return 'bg-orange-500';
    if (score >= 35) return 'bg-amber-500';
    if (score > 0) return 'bg-emerald-500';
    return 'bg-slate-500';
  };

  return (
    <div className="flex flex-col items-center justify-center p-4 bg-slate-900/60 rounded-xl border border-slate-800">
      <div className="flex items-baseline gap-1">
        <span className={`text-4xl font-extrabold tracking-tight font-['JetBrains_Mono'] ${getColor()}`}>
          {score}
        </span>
        <span className="text-xs font-semibold text-slate-500">/100</span>
      </div>
      <span className="text-xs font-medium text-slate-400 mt-1 uppercase tracking-wider">
        Threat Score
      </span>
      <div className="w-full bg-slate-800 rounded-full h-2 mt-3 overflow-hidden">
        <div
          className={`h-full transition-all duration-700 ease-out ${getProgressColor()}`}
          style={{ width: `${Math.max(5, Math.min(100, score))}%` }}
        />
      </div>
    </div>
  );
};
