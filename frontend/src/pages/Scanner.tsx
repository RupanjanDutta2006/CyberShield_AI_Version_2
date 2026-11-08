import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Search,
  Shield,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Server
} from 'lucide-react';
import { scanUrl } from '../services/api';
import { ScanDetail } from '../types';
import { RiskBadge } from '../components/RiskBadge';
import { ScoreGauge } from '../components/ScoreGauge';
import { VerificationCard } from '../components/VerificationCard';

export const Scanner: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [inputUrl, setInputUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Sample quick test buttons
  const samples = [
    { label: 'Synthetic Malware C2', url: 'https://test-malware.cyber/payload.exe' },
    { label: 'Synthetic Phish Login', url: 'https://test-phish.cyber/banking/auth' },
    { label: 'Suspicious IP Literal', url: 'http://185.220.101.5:8080/admin' },
    { label: 'Clean Baseline', url: 'https://example.com' },
  ];

  useEffect(() => {
    const urlParam = searchParams.get('url');
    if (urlParam) {
      setInputUrl(urlParam);
      executeScan(urlParam);
    }
  }, [searchParams]);

  const executeScan = async (target: string) => {
    if (!target.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await scanUrl(target.trim());
      setResult(data);
    } catch (err: any) {
      setError(
        err?.response?.data?.detail ||
          'Failed to execute threat intelligence scan. Please verify target syntax.'
      );
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeScan(inputUrl);
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Page Title & Intro */}
      <div>
        <div className="flex items-center gap-2 text-cyan-400 text-xs font-bold uppercase tracking-wider mb-1">
          <Shield size={14} /> Multi-Provider Threat Evaluation
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-100">
          URL & Domain Reputation Scanner
        </h1>
        <p className="text-sm text-slate-400 mt-1 max-w-2xl">
          Queries threat intelligence feeds without downloading or executing the target.
          Evaluates malicious payloads, domain heuristics, and outputs a tamper-evident risk report.
        </p>
      </div>

      {/* Input Box Card */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 sm:p-8">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="relative">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500 w-5 h-5" />
            <input
              type="text"
              placeholder="Enter URL, hostname, or IP (e.g., https://login-verify-account.top/auth)"
              value={inputUrl}
              onChange={(e) => setInputUrl(e.target.value)}
              className="w-full pl-12 pr-32 py-4 bg-slate-950/90 border border-slate-700 rounded-xl text-slate-100 placeholder-slate-500 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-['JetBrains_Mono'] transition-all"
            />
            <button
              type="submit"
              disabled={loading || !inputUrl.trim()}
              className="absolute right-2 top-1/2 -translate-y-1/2 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold rounded-lg flex items-center gap-2 shadow-md shadow-cyan-600/20 transition-all disabled:opacity-50"
            >
              {loading ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Shield size={14} /> Scan URL
                </>
              )}
            </button>
          </div>

          {/* Quick presets */}
          <div className="flex flex-wrap items-center gap-2 pt-2 text-xs text-slate-400">
            <span className="font-semibold text-slate-500">Quick Test Samples:</span>
            {samples.map((s) => (
              <button
                key={s.label}
                type="button"
                onClick={() => {
                  setInputUrl(s.url);
                  executeScan(s.url);
                }}
                className="px-2.5 py-1 rounded-md bg-slate-800/80 hover:bg-slate-700/80 text-slate-300 border border-slate-700 transition-colors"
              >
                {s.label}
              </button>
            ))}
          </div>
        </form>

        {error && (
          <div className="mt-4 p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2.5">
            <AlertTriangle size={16} className="shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Loading Radar Animation */}
      {loading && (
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-12 text-center space-y-4">
          <div className="relative w-16 h-16 mx-auto">
            <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20 animate-ping" />
            <div className="w-16 h-16 rounded-full border-2 border-cyan-500/40 border-t-cyan-400 animate-spin flex items-center justify-center">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
          </div>
          <div>
            <h4 className="text-base font-bold text-slate-100">Analyzing Target Destination</h4>
            <p className="text-xs text-slate-400 mt-1">
              Normalizing URL syntax &bull; Interrogating URLhaus &amp; PhishTank &bull; Evaluating heuristics
            </p>
          </div>
        </div>
      )}

      {/* Scan Results Display */}
      {result && !loading && (
        <div className="space-y-8">
          {/* Target Overview Card */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 sm:p-8">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-center">
              <div className="lg:col-span-2 space-y-4">
                <div className="flex flex-wrap items-center gap-3">
                  <RiskBadge level={result.risk_level} size="lg" />
                  <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-700 capitalize">
                    {result.scan_type} Target
                  </span>
                  {(result.domain?.endsWith('.example') || result.hostname?.endsWith('.example') || result.domain?.endsWith('.test')) && (
                    <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-sky-500/20 text-sky-300 border border-sky-500/30">
                      RFC 2606 Reserved Test Domain
                    </span>
                  )}
                  <span className="text-xs text-slate-400">
                    Scan ID: <span className="font-['JetBrains_Mono']">{result.scan_id.slice(0, 8)}...</span>
                  </span>
                </div>

                <div>
                  <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                    Defanged Target (Safe for Display)
                  </label>
                  <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl font-['JetBrains_Mono'] text-xs text-cyan-300 break-all select-all">
                    {result.normalized_target || result.target}
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs pt-1">
                  <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase font-semibold">Domain</span>
                    <span className="text-slate-200 font-['JetBrains_Mono']">{result.domain || 'N/A'}</span>
                  </div>
                  <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase font-semibold">Hostname</span>
                    <span className="text-slate-200 font-['JetBrains_Mono']">{result.hostname || 'N/A'}</span>
                  </div>
                  <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800 col-span-2 sm:col-span-1">
                    <span className="text-slate-500 block text-[10px] uppercase font-semibold">Triage Status</span>
                    <span className="text-emerald-400 font-semibold uppercase">{result.status}</span>
                  </div>
                </div>
              </div>

              {/* Threat Score Gauge */}
              <div className="flex justify-center">
                <ScoreGauge score={result.risk_score} riskLevel={result.risk_level} />
              </div>
            </div>
          </div>

          {/* Intelligence Feeds Breakdown */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
              <Server size={16} className="text-cyan-400" /> Threat Intelligence Provider Findings
            </h3>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase font-semibold">
                    <th className="pb-3 pl-2">Security Provider</th>
                    <th className="pb-3">Query Verdict</th>
                    <th className="pb-3">Confidence Status</th>
                    <th className="pb-3">Reference Link</th>
                    <th className="pb-3 text-right pr-2">Granular Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {result.providers_checked.map((prov) => (
                    <tr key={prov.provider} className="hover:bg-slate-800/20">
                      <td className="py-3.5 pl-2 font-bold text-slate-200">{prov.provider}</td>
                      <td className="py-3.5">
                        {prov.matched ? (
                          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-red-500/20 text-red-400 border border-red-500/30">
                            Threat Match Found
                          </span>
                        ) : prov.status === 'clean' ? (
                          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                            No Match (Clean)
                          </span>
                        ) : prov.status === 'not_configured' ? (
                          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-400">
                            Key Not Configured
                          </span>
                        ) : prov.status === 'skipped_synthetic' ? (
                          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-sky-500/20 text-sky-400 border border-sky-500/30">
                            Reserved / Test Domain
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                            {prov.status}
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 text-slate-400">
                        {prov.verified ? 'Analyst / Feed Verified' : 'Community / Unverified'}
                      </td>
                      <td className="py-3.5">
                        {prov.reference ? (
                          <a
                            href={prov.reference}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-cyan-400 hover:underline inline-flex items-center gap-1"
                          >
                            Intel Dossier <ExternalLink size={11} />
                          </a>
                        ) : (
                          <span className="text-slate-600">None</span>
                        )}
                      </td>
                      <td className="py-3.5 text-right pr-2 font-['JetBrains_Mono'] text-[11px] text-slate-400">
                        {prov.details?.threat || prov.details?.query_status || JSON.stringify(prov.details || {})}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Evidence and Recommendations Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Evidence Card */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
                <AlertTriangle size={16} className="text-amber-400" /> Evidence &amp; Detection Indicators
              </h3>
              {result.report.evidence.length > 0 ? (
                <ul className="space-y-2.5">
                  {result.report.evidence.map((ev, idx) => (
                    <li
                      key={idx}
                      className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs text-slate-300 flex items-start gap-2.5"
                    >
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                      <span>{ev}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-slate-500">No adverse evidence detected for this target.</p>
              )}
            </div>

            {/* Recommendations Card */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
                <CheckCircle2 size={16} className="text-emerald-400" /> Recommended Cybersecurity Actions
              </h3>
              <ul className="space-y-2.5">
                {result.report.recommendations.map((rec, idx) => (
                  <li
                    key={idx}
                    className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs text-slate-300 flex items-start gap-2.5"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Report Cryptographic Integrity Card */}
          <VerificationCard
            reportId={result.report.report_id}
            reportHash={result.report.report_hash}
            initialStatus={result.report.verification_status}
            blockchainTx={result.report.blockchain_tx}
          />
        </div>
      )}
    </div>
  );
};
