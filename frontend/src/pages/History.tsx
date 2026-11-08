import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  History as HistoryIcon,
  Search,
  RefreshCw,
  ArrowRight,
  FileText
} from 'lucide-react';
import { getScans } from '../services/api';
import { ScanListItem } from '../types';
import { RiskBadge } from '../components/RiskBadge';

export const History: React.FC = () => {
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRisk, setSelectedRisk] = useState<string>('All');
  const [selectedType, setSelectedType] = useState<string>('All');

  const riskFilters = ['All', 'Critical', 'High', 'Medium', 'Low', 'Unknown'];

  const fetchScans = async () => {
    setLoading(true);
    try {
      const data = await getScans({
        query: searchQuery.trim() || undefined,
        risk_level: selectedRisk !== 'All' ? selectedRisk : undefined,
        scan_type: selectedType !== 'All' ? selectedType : undefined,
        limit: 50,
      });
      setScans(data.items);
      setTotal(data.total);
    } catch (err) {
      console.error('Failed to load scan history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, [selectedRisk, selectedType]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchScans();
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-bold uppercase tracking-wider mb-1">
            <HistoryIcon size={14} /> Investigation Registry
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-100">
            Threat Scan History
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Audit log of all analyzed URLs, domains, and phishing communications.
          </p>
        </div>

        <button
          onClick={fetchScans}
          disabled={loading}
          className="self-start sm:self-auto px-4 py-2.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 text-xs font-semibold text-slate-300 flex items-center gap-2 transition-all"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          Refresh Registry
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-5 space-y-4">
        <div className="flex flex-col md:flex-row gap-3">
          {/* Search Input */}
          <form onSubmit={handleSearchSubmit} className="relative flex-grow">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 w-4 h-4" />
            <input
              type="text"
              placeholder="Search by target URL, domain, or preview..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-500 text-xs focus:outline-none focus:border-cyan-500 font-['JetBrains_Mono']"
            />
          </form>

          {/* Type Filter */}
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="px-3 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-slate-300 text-xs focus:outline-none focus:border-cyan-500 font-sans"
          >
            <option value="All">All Scan Types</option>
            <option value="url">URL Scans</option>
            <option value="message">Message Scans</option>
          </select>
        </div>

        {/* Risk Level Pills */}
        <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-slate-800/60">
          <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mr-1">
            Severity:
          </span>
          {riskFilters.map((risk) => (
            <button
              key={risk}
              type="button"
              onClick={() => setSelectedRisk(risk)}
              className={`px-3 py-1 rounded-lg text-xs font-semibold transition-all ${
                selectedRisk === risk
                  ? 'bg-cyan-500 text-slate-950 shadow-sm shadow-cyan-500/30'
                  : 'bg-slate-950/80 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              {risk}
            </button>
          ))}
          <span className="ml-auto text-xs text-slate-500">
            Found <strong>{total}</strong> investigations
          </span>
        </div>
      </div>

      {/* Scans Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden">
        {loading ? (
          <div className="py-20 text-center text-slate-500 text-xs space-y-3">
            <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto" />
            <p>Loading registry records...</p>
          </div>
        ) : scans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/50 text-slate-400 uppercase font-semibold">
                  <th className="py-3.5 pl-4">Target / Pretext Preview</th>
                  <th className="py-3.5">Type</th>
                  <th className="py-3.5">Risk Level</th>
                  <th className="py-3.5">Score</th>
                  <th className="py-3.5">Cryptographic Proof</th>
                  <th className="py-3.5">Investigated At</th>
                  <th className="py-3.5 text-right pr-4">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-['JetBrains_Mono']">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3.5 pl-4 font-medium text-slate-200 max-w-xs truncate">
                      {scan.target}
                    </td>
                    <td className="py-3.5 text-slate-400 font-sans capitalize">
                      {scan.scan_type}
                    </td>
                    <td className="py-3.5 font-sans">
                      <RiskBadge level={scan.risk_level} size="sm" />
                    </td>
                    <td className="py-3.5 font-bold text-slate-300">
                      {scan.risk_score}/100
                    </td>
                    <td className="py-3.5 text-slate-500 text-[11px]">
                      {scan.report_hash ? `${scan.report_hash.slice(0, 14)}...` : 'N/A'}
                    </td>
                    <td className="py-3.5 text-slate-400 font-sans">
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                    <td className="py-3.5 text-right pr-4 font-sans">
                      <Link
                        to={`/report/${scan.id}`}
                        className="px-3 py-1.5 rounded-lg bg-cyan-600/10 hover:bg-cyan-600/20 text-cyan-400 border border-cyan-500/20 text-xs font-semibold inline-flex items-center gap-1 transition-all"
                      >
                        Dossier <ArrowRight size={11} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-16 text-center text-slate-500 text-xs space-y-2">
            <FileText size={24} className="mx-auto text-slate-600" />
            <p className="font-semibold text-slate-400">No matching threat records found</p>
            <p>Try adjusting your search criteria or run a new scan from the dashboard.</p>
          </div>
        )}
      </div>
    </div>
  );
};
