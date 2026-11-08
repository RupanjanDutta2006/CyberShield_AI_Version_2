import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Clock,
  Server,
  AlertTriangle,
  CheckCircle2,
  Activity,
  ExternalLink
} from 'lucide-react';
import { getScanById } from '../services/api';
import { ScanDetail } from '../types';
import { RiskBadge } from '../components/RiskBadge';
import { ScoreGauge } from '../components/ScoreGauge';
import { VerificationCard } from '../components/VerificationCard';

export const ReportDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDetails = async () => {
      if (!id) return;
      setLoading(true);
      try {
        const data = await getScanById(id);
        setScan(data);
      } catch (err: any) {
        setError(err?.response?.data?.detail || 'Failed to retrieve investigation record.');
      } finally {
        setLoading(false);
      }
    };
    fetchDetails();
  }, [id]);

  if (loading) {
    return (
      <div className="max-w-5xl mx-auto px-4 py-20 text-center space-y-3">
        <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto" />
        <p className="text-xs text-slate-400">Loading comprehensive investigation dossier...</p>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="max-w-3xl mx-auto px-4 py-16 text-center space-y-4">
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-sm">
          {error || 'Investigation record could not be located.'}
        </div>
        <Link
          to="/history"
          className="inline-flex items-center gap-2 text-xs font-semibold text-cyan-400 hover:underline"
        >
          <ArrowLeft size={14} /> Return to Investigation Registry
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Navigation Breadcrumb */}
      <div className="flex items-center justify-between">
        <Link
          to="/history"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400 hover:text-slate-200 transition-colors"
        >
          <ArrowLeft size={14} /> Back to Registry
        </Link>
        <span className="text-xs text-slate-500 font-['JetBrains_Mono']">
          UUID: {scan.scan_id}
        </span>
      </div>

      {/* Main Dossier Banner */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 sm:p-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-center">
          <div className="lg:col-span-2 space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <RiskBadge level={scan.risk_level} size="lg" />
              <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-700 capitalize">
                {scan.scan_type} Target
              </span>
              <span className="text-xs text-slate-400 flex items-center gap-1 font-sans">
                <Clock size={12} /> {new Date(scan.created_at).toUTCString()}
              </span>
            </div>

            <div>
              <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                Target Under Investigation
              </label>
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl font-['JetBrains_Mono'] text-xs text-cyan-300 break-all select-all">
                {scan.target}
              </div>
            </div>

            <p className="text-sm text-slate-300 leading-relaxed font-sans">
              {scan.report?.summary}
            </p>
          </div>

          {/* Calibrated Gauge */}
          <div className="flex justify-center">
            <ScoreGauge score={scan.risk_score} riskLevel={scan.risk_level} />
          </div>
        </div>
      </div>

      {/* Detected Threat Indicators Breakdown (for Message Scans) */}
      {scan.message_indicators && scan.message_indicators.length > 0 && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
            <AlertTriangle size={16} className="text-amber-400" /> Specific Phishing Indicators Detected
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
            {scan.message_indicators.map((ind, i) => (
              <div
                key={i}
                className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start gap-3"
              >
                <div
                  className={`p-2 rounded-lg shrink-0 ${
                    ind.severity === 'Critical'
                      ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                      : ind.severity === 'High'
                      ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                      : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                  }`}
                >
                  <AlertTriangle size={16} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-slate-200">{ind.category}</span>
                    <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                      {ind.severity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mt-1">{ind.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Provider Intelligence Findings Table */}
      {scan.providers_checked && scan.providers_checked.length > 0 && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Server size={16} className="text-cyan-400" /> Threat Intelligence Feed Query Results
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase font-semibold">
                  <th className="pb-3 pl-2">Provider Feed</th>
                  <th className="pb-3">Indicator Type</th>
                  <th className="pb-3">Query Verdict</th>
                  <th className="pb-3">Verification</th>
                  <th className="pb-3 text-right pr-2">Reference / Dossier</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-['JetBrains_Mono']">
                {scan.providers_checked.map((prov, i) => (
                  <tr key={i} className="hover:bg-slate-800/20">
                    <td className="py-3 pl-2 font-bold text-slate-200 font-sans">{prov.provider}</td>
                    <td className="py-3 text-slate-400">{prov.indicator_type}</td>
                    <td className="py-3 font-sans">
                      {prov.matched ? (
                        <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-red-500/20 text-red-400 border border-red-500/30">
                          Threat Matched
                        </span>
                      ) : prov.status === 'clean' ? (
                        <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                          Clean (No Blacklist Match)
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-slate-800 text-slate-400">
                          {prov.status}
                        </span>
                      )}
                    </td>
                    <td className="py-3 text-slate-400 font-sans">
                      {prov.verified ? 'Verified Active Feed' : 'Unverified / Fallback'}
                    </td>
                    <td className="py-3 text-right pr-2">
                      {prov.reference ? (
                        <a
                          href={prov.reference}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-cyan-400 hover:underline inline-flex items-center gap-1 font-sans"
                        >
                          Source Link <ExternalLink size={11} />
                        </a>
                      ) : (
                        <span className="text-slate-600 font-sans">None</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Evidence and Recommendations Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Evidence Card */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
            <AlertTriangle size={16} className="text-amber-400" /> Evidence &amp; Indicators
          </h3>
          {scan.report?.evidence && scan.report.evidence.length > 0 ? (
            <ul className="space-y-2.5">
              {scan.report.evidence.map((ev, idx) => (
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
            <p className="text-xs text-slate-500">No adverse threat indicators logged.</p>
          )}
        </div>

        {/* Recommendations Card */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
            <CheckCircle2 size={16} className="text-emerald-400" /> Prescribed Mitigation Steps
          </h3>
          <ul className="space-y-2.5">
            {scan.report?.recommendations.map((rec, idx) => (
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

      {/* Audit Events Timeline */}
      {scan.events && scan.events.length > 0 && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Activity size={16} className="text-cyan-400" /> Transparent Investigation Audit Trail
          </h3>
          <div className="space-y-3 font-['JetBrains_Mono'] text-xs">
            {scan.events.map((ev, i) => (
              <div key={i} className="flex items-start gap-3 p-3 rounded-xl bg-slate-950/50 border border-slate-800/60">
                <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-800 text-cyan-300 shrink-0">
                  {ev.event_type}
                </span>
                <span className="text-slate-300 font-sans flex-grow">{ev.description}</span>
                <span className="text-[11px] text-slate-500 shrink-0 font-sans">
                  {new Date(ev.created_at).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Cryptographic Report Verification Card */}
      {scan.report && (
        <VerificationCard
          reportId={scan.report.report_id}
          reportHash={scan.report.report_hash}
          initialStatus={scan.report.verification_status}
          blockchainTx={scan.report.blockchain_tx}
        />
      )}
    </div>
  );
};
