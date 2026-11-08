import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Shield,
  Search,
  AlertTriangle,
  CheckCircle,
  Clock,
  ArrowRight,
  TrendingUp,
  Server,
  Terminal,
  Zap
} from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';
import { getStats, getSystemStatus } from '../services/api';
import { StatsOverviewResponse, SystemStatusResponse } from '../types';
import { RiskBadge } from '../components/RiskBadge';

const RISK_COLORS: Record<string, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#f59e0b',
  Low: '#10b981',
  Unknown: '#64748b',
};

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [stats, setStats] = useState<StatsOverviewResponse | null>(null);
  const [system, setSystem] = useState<SystemStatusResponse | null>(null);
  const [quickUrl, setQuickUrl] = useState('');
  const [, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsData, sysData] = await Promise.all([getStats(), getSystemStatus()]);
        setStats(statsData);
        setSystem(sysData);
      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const handleQuickScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (quickUrl.trim()) {
      navigate(`/scanner?url=${encodeURIComponent(quickUrl.trim())}`);
    }
  };

  const chartData = stats?.risk_distribution
    ? Object.entries(stats.risk_distribution).map(([name, value]) => ({
        name,
        value,
      }))
    : [];

  return (
    <div className="space-y-8 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Hero Header with Quick Scan */}
      <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-slate-900 via-[#0d1424] to-[#0a0d14] border border-slate-800 p-8 sm:p-10 shadow-2xl">
        <div className="absolute top-0 right-0 -mt-10 -mr-10 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl -z-10" />
        <div className="max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 text-xs font-semibold mb-4">
            <Zap size={13} /> Next-Gen AI Cyber Threat Intelligence
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-100 tracking-tight leading-tight">
            Comprehensive Threat Detection & Automated Triage
          </h1>
          <p className="mt-3 text-slate-400 text-sm sm:text-base leading-relaxed">
            Scan suspicious links, verify domain reputation against authoritative feeds, analyze phishing pretexts, and generate cryptographic SHA-256 audit reports.
          </p>

          {/* Quick Scan Input Form */}
          <form onSubmit={handleQuickScan} className="mt-6 flex flex-col sm:flex-row gap-3">
            <div className="relative flex-grow">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500 w-5 h-5" />
              <input
                type="text"
                placeholder="Enter URL or domain (e.g. https://secure-bank-login.xyz)"
                value={quickUrl}
                onChange={(e) => setQuickUrl(e.target.value)}
                className="w-full pl-12 pr-4 py-3.5 bg-slate-950/80 border border-slate-700 rounded-xl text-slate-100 placeholder-slate-500 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-['JetBrains_Mono'] transition-all"
              />
            </div>
            <button
              type="submit"
              className="px-6 py-3.5 bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold rounded-xl flex items-center justify-center gap-2 shadow-lg shadow-cyan-600/25 transition-all shrink-0"
            >
              <Shield size={16} /> Scan Target
            </button>
          </form>
        </div>
      </div>

      {/* Primary Telemetry Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Total Scans Executed</span>
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
              <TrendingUp size={16} />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-100 font-['JetBrains_Mono']">
              {stats?.total_scans ?? 0}
            </span>
            <span className="text-xs text-slate-500">records</span>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Malicious Threats</span>
            <div className="p-2 rounded-lg bg-red-500/10 text-red-400">
              <AlertTriangle size={16} />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-red-400 font-['JetBrains_Mono']">
              {stats?.malicious_count ?? 0}
            </span>
            <span className="text-xs text-red-500/80">blocked</span>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Suspicious / Medium</span>
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400">
              <Clock size={16} />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-amber-400 font-['JetBrains_Mono']">
              {stats?.suspicious_count ?? 0}
            </span>
            <span className="text-xs text-amber-500/80">flagged</span>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 hover:border-slate-700 transition-all">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Clean / Benign</span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
              <CheckCircle size={16} />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-emerald-400 font-['JetBrains_Mono']">
              {stats?.benign_count ?? 0}
            </span>
            <span className="text-xs text-emerald-500/80">verified</span>
          </div>
        </div>
      </div>

      {/* Middle Grid: Threat Breakdown Chart & Threat Intelligence Feeds */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Distribution Chart */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center justify-between">
            <span>Threat Severity Profile</span>
            <span className="text-xs text-slate-500 font-normal">Global</span>
          </h3>

          <div className="h-52 w-full flex items-center justify-center">
            {chartData.length > 0 && stats?.total_scans ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={chartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {chartData.map((entry) => (
                      <Cell
                        key={`cell-${entry.name}`}
                        fill={RISK_COLORS[entry.name] || '#64748b'}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0a0d14',
                      borderColor: '#1e293b',
                      borderRadius: '8px',
                      fontSize: '12px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-center text-slate-500 text-xs">
                No telemetry recorded yet. Perform a scan to populate distribution charts.
              </div>
            )}
          </div>

          <div className="grid grid-cols-3 gap-2 pt-4 border-t border-slate-800/80 text-xs text-slate-400">
            {['Critical', 'High', 'Medium', 'Low'].map((level) => (
              <div key={level} className="flex items-center gap-1.5">
                <span
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: RISK_COLORS[level] }}
                />
                <span>{level}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Intelligence Feeds & Engine Status */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 rounded-2xl p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <Server size={16} className="text-cyan-400" /> Connected Intelligence Engines
              </h3>
              <Link
                to="/settings"
                className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                Configure APIs <ArrowRight size={12} />
              </Link>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
              {system?.providers.map((p) => (
                <div
                  key={p.provider_name}
                  className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800/80 flex items-start justify-between gap-3"
                >
                  <div>
                    <div className="text-xs font-semibold text-slate-200">
                      {p.provider_name}
                    </div>
                    <div className="text-[11px] text-slate-400 mt-0.5 line-clamp-1">
                      {p.details}
                    </div>
                  </div>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded-full font-semibold uppercase tracking-wider shrink-0 ${
                      p.status === 'active'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : p.status === 'community_fallback' || p.status === 'local_sha256_active' || p.status === 'heuristic_fallback'
                        ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/25'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {p.status.replace('_', ' ')}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-5 p-3 rounded-xl bg-cyan-950/20 border border-cyan-800/30 flex items-center justify-between text-xs text-cyan-300">
            <span className="flex items-center gap-2">
              <Terminal size={14} /> Database Engine: <strong>{system?.database_type}</strong>
            </span>
            <span className="text-[11px] text-slate-400">Zero-Crash Architecture</span>
          </div>
        </div>
      </div>

      {/* Recent Scans Feed */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h3 className="text-base font-bold text-slate-100">Recent Threat Investigations</h3>
            <p className="text-xs text-slate-400">Latest URLs and messages evaluated by the platform</p>
          </div>
          <Link
            to="/history"
            className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
          >
            Full Investigation History <ArrowRight size={13} />
          </Link>
        </div>

        {stats?.recent_scans && stats.recent_scans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  <th className="pb-3 pl-2">Target</th>
                  <th className="pb-3">Type</th>
                  <th className="pb-3">Risk Assessment</th>
                  <th className="pb-3">Score</th>
                  <th className="pb-3">Investigated At</th>
                  <th className="pb-3 text-right pr-2">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-['JetBrains_Mono'] text-xs">
                {stats.recent_scans.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 pl-2 font-medium text-slate-200 max-w-xs truncate">
                      {item.target}
                    </td>
                    <td className="py-3 text-slate-400 capitalize">{item.scan_type}</td>
                    <td className="py-3 font-sans">
                      <RiskBadge level={item.risk_level} size="sm" />
                    </td>
                    <td className="py-3 text-slate-300 font-bold">{item.risk_score}/100</td>
                    <td className="py-3 text-slate-400 font-sans text-xs">
                      {new Date(item.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 text-right pr-2 font-sans">
                      <Link
                        to={`/report/${item.id}`}
                        className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 hover:underline inline-flex items-center gap-1"
                      >
                        Inspect <ArrowRight size={11} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-12 text-center text-slate-500 text-sm">
            No scans recorded yet. Use the scanner above to run your first threat intelligence audit.
          </div>
        )}
      </div>
    </div>
  );
};
