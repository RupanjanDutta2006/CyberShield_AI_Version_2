import React, { useState } from 'react';
import {
  MessageSquare,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Cpu,
  ArrowRight,
  FileText
} from 'lucide-react';
import { scanMessage } from '../services/api';
import { ScanDetail } from '../types';
import { RiskBadge } from '../components/RiskBadge';
import { ScoreGauge } from '../components/ScoreGauge';
import { VerificationCard } from '../components/VerificationCard';

export const MessageAnalyzer: React.FC = () => {
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  const presets = [
    {
      title: 'Bank Urgency & Credential Theft',
      text: 'URGENT SECURITY ALERT: Your primary checking account has been flagged for suspicious unauthorized activity. Your access will be permanently suspended within 24 hours. Immediately confirm your password, banking login, and PIN code at: https://verify-secure-bank.cc/auth',
    },
    {
      title: 'Telegram Part-Time / Fake Job Scam',
      text: 'Congratulations! You have been selected for part-time remote work at Amazon. Earn Rs 5,000 daily by rating products on Telegram. Deposit mandatory registration fee of Rs 1,500 to activate your worker ID: https://bit.ly/fake-job-pay',
    },
    {
      title: 'Electricity Disconnection / Fake APK Scam',
      text: 'URGENT: Your electricity power supply will be disconnected tonight at 9:30 PM due to unpaid bill of Rs 3,420. Immediately call electricity officer at +91-9876543210 or install BijliUpdate.apk to update KYC.',
    },
    {
      title: 'Executive Wire Transfer Pretext (BEC)',
      text: 'Good morning, this is the Chief Executive Officer. I am currently in a closed-door acquisition meeting and cannot take calls. Please process an immediate wire transfer for $48,500 to our new supplier account before 2:00 PM today. Treat this request with utmost confidentiality.',
    },
    {
      title: 'Microsoft 365 Account Expiry',
      text: 'Action Required: Your Microsoft 365 organizational password expires today. Click the link below to verify your login credentials and retain uninterrupted mailbox access: https://login.microsoftonline.security-portal.xyz/verify',
    },
    {
      title: 'Benign Corporate Newsletter',
      text: 'Hello team, please find attached the monthly cyber security awareness newsletter. This edition covers safe remote working practices and password manager recommendations. Have a wonderful weekend!',
    },
  ];

  const handleAnalyze = async (textToScan?: string) => {
    const text = textToScan ?? content;
    if (!text.trim() || text.length < 5) {
      setError('Please provide a message with at least 5 characters for analysis.');
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const data = await scanMessage(text);
      setResult(data);
    } catch (err: any) {
      setError(
        err?.response?.data?.detail || 'Failed to analyze message content. Please try again.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Title */}
      <div>
        <div className="flex items-center gap-2 text-cyan-400 text-xs font-bold uppercase tracking-wider mb-1">
          <MessageSquare size={14} /> Social Engineering &amp; Phishing Detection
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-100">
          AI &amp; Heuristic Message Analyzer
        </h1>
        <p className="text-sm text-slate-400 mt-1 max-w-2xl">
          Paste suspicious emails, SMS messages, or employee outreach to detect pressure tactics,
          credential harvesting indicators, executive impersonation, and fraudulent payment coercion.
        </p>
      </div>

      {/* Input Box Card */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 sm:p-8 space-y-5">
        <div>
          <label className="text-xs font-bold text-slate-300 uppercase tracking-wider block mb-2">
            Message Body / Email Content
          </label>
          <textarea
            rows={5}
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Paste suspicious email text, SMS message, or chat snippet here..."
            className="w-full p-4 bg-slate-950/90 border border-slate-700 rounded-xl text-slate-100 placeholder-slate-500 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-sans transition-all leading-relaxed"
          />
        </div>

        {/* Attack Presets */}
        <div>
          <span className="text-xs font-semibold text-slate-400 block mb-2">
            Or select a representative phishing scenario to evaluate:
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {presets.map((preset) => (
              <button
                key={preset.title}
                type="button"
                onClick={() => {
                  setContent(preset.text);
                  handleAnalyze(preset.text);
                }}
                className="text-left p-3 rounded-xl bg-slate-950/60 hover:bg-slate-800/60 border border-slate-800 hover:border-slate-700 transition-all group"
              >
                <div className="text-xs font-bold text-slate-200 group-hover:text-cyan-300 flex items-center justify-between">
                  <span>{preset.title}</span>
                  <ArrowRight size={12} className="opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
                <div className="text-[11px] text-slate-400 line-clamp-1 mt-1 font-mono">
                  {preset.text}
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Action button */}
        <div className="flex items-center justify-between pt-2">
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <Cpu size={14} className="text-cyan-400" />
            <span>Multi-Tier Inspection: Local Heuristics + Optional Gemini AI</span>
          </div>

          <button
            onClick={() => handleAnalyze()}
            disabled={loading || !content.trim()}
            className="px-6 py-3 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold rounded-xl flex items-center gap-2 shadow-lg shadow-cyan-600/20 transition-all disabled:opacity-50"
          >
            {loading ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Evaluating Phishing Intent...
              </>
            ) : (
              <>
                <Shield size={14} /> Analyze Threat Indicators
              </>
            )}
          </button>
        </div>

        {error && (
          <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2.5">
            <AlertTriangle size={16} className="shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Analysis Results Display */}
      {result && !loading && (
        <div className="space-y-8">
          {/* Top Overview Banner */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 sm:p-8">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-center">
              <div className="lg:col-span-2 space-y-4">
                <div className="flex flex-wrap items-center gap-3">
                  <RiskBadge level={result.risk_level} size="lg" />
                  <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-700 capitalize">
                    Engine: {result.analysis_engine?.replace(/_/g, ' ') || 'Deterministic Rule Engine'}
                  </span>
                </div>

                <div>
                  <h3 className="text-lg font-bold text-slate-100">
                    {result.report.summary}
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Evaluated against psychological pressure tactics, sensitive keyword requests, and identity pretexting.
                  </p>
                </div>
              </div>

              {/* Threat Score Gauge */}
              <div className="flex justify-center">
                <ScoreGauge score={result.risk_score} riskLevel={result.risk_level} />
              </div>
            </div>
          </div>

          {/* Detected Threat Indicators Breakdown */}
          {result.message_indicators && result.message_indicators.length > 0 && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
                <AlertTriangle size={16} className="text-amber-400" /> Specific Phishing Indicators Detected
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                {result.message_indicators.map((ind, i) => (
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

          {/* Evidence and Recommendations Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Evidence Card */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
                <FileText size={16} className="text-cyan-400" /> Forensic Evidence Summary
              </h3>
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
            </div>

            {/* Recommendations Card */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
              <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
                <CheckCircle2 size={16} className="text-emerald-400" /> Prescribed User Response
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

          {/* Cryptographic Verification Card */}
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
