import React, { useState } from 'react';
import { ShieldCheck, CheckCircle2, XCircle, RefreshCw, AlertTriangle, Fingerprint } from 'lucide-react';
import { verifyReport } from '../services/api';
import { VerifyReportResponse } from '../types';

interface VerificationCardProps {
  reportId: string;
  reportHash: string;
  initialStatus: string;
  blockchainTx?: string | null;
}

export const VerificationCard: React.FC<VerificationCardProps> = ({
  reportId,
  reportHash,
  initialStatus,
  blockchainTx
}) => {
  const [loading, setLoading] = useState(false);
  const [verificationResult, setVerificationResult] = useState<VerifyReportResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleVerify = async (tamperedText?: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await verifyReport(reportId, tamperedText);
      setVerificationResult(res);
    } catch (err: any) {
      setError(err?.response?.data?.detail || 'Failed to verify report integrity.');
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'blockchain_verified':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-violet-500/20 text-violet-300 border border-violet-500/30">
            <CheckCircle2 size={12} /> Blockchain Anchored
          </span>
        );
      case 'verification_failed':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-red-500/20 text-red-300 border border-red-500/30 animate-pulse">
            <XCircle size={12} /> Integrity Compromised
          </span>
        );
      case 'locally_hashed':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
            <Fingerprint size={12} /> Locally Hashed (SHA-256)
          </span>
        );
    }
  };

  const currentStatus = verificationResult
    ? verificationResult.verification_status
    : initialStatus;

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 relative overflow-hidden">
      {/* Background Accent */}
      <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl -z-10" />

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <ShieldCheck size={22} />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              Report Integrity Verification
            </h3>
            <p className="text-xs text-slate-400">
              Deterministic RFC 8785 canonical hash proof
            </p>
          </div>
        </div>
        <div>{getStatusBadge(currentStatus)}</div>
      </div>

      {/* Hash display */}
      <div className="my-5">
        <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1.5">
          SHA-256 Canonical Fingerprint
        </label>
        <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-xl font-['JetBrains_Mono'] text-xs text-cyan-300/90 break-all select-all flex items-center justify-between gap-2">
          <span>{reportHash}</span>
        </div>
      </div>

      {/* Blockchain Tx if available */}
      {blockchainTx && (
        <div className="mb-5 p-3 rounded-xl bg-violet-950/30 border border-violet-800/40 text-xs">
          <span className="font-semibold text-violet-300">Blockchain Transaction: </span>
          <span className="font-['JetBrains_Mono'] text-violet-200 select-all">{blockchainTx}</span>
        </div>
      )}

      {/* Verification Result Feedback */}
      {verificationResult && (
        <div
          className={`p-4 rounded-xl border mb-5 text-xs transition-all ${
            verificationResult.is_valid
              ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
              : 'bg-red-950/40 border-red-500/50 text-red-300'
          }`}
        >
          <div className="flex items-start gap-2.5">
            {verificationResult.is_valid ? (
              <CheckCircle2 size={16} className="text-emerald-400 mt-0.5 shrink-0" />
            ) : (
              <AlertTriangle size={16} className="text-red-400 mt-0.5 shrink-0" />
            )}
            <div>
              <p className="font-semibold text-sm">
                {verificationResult.is_valid
                  ? 'Verification Successful — Authentic Report'
                  : 'Tampering Alert — Integrity Check Failed!'}
              </p>
              <p className="text-slate-300 mt-1">{verificationResult.audit_notes}</p>
              <div className="mt-2 text-[11px] font-['JetBrains_Mono'] opacity-80">
                Recalculated: {verificationResult.recalculated_hash}
              </div>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="p-3 rounded-xl bg-red-950/30 border border-red-500/30 text-xs text-red-400 mb-4">
          {error}
        </div>
      )}

      {/* Action Buttons */}
      <div className="flex flex-wrap items-center gap-3 pt-2">
        <button
          onClick={() => handleVerify()}
          disabled={loading}
          className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white transition-all shadow-md shadow-cyan-600/20 disabled:opacity-50"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          {loading ? 'Recomputing Hash...' : 'Verify Cryptographic Integrity'}
        </button>

        <button
          onClick={() => handleVerify('MALICIOUS_SIMULATION_TAMPERED_INJECTED_STRING')}
          disabled={loading}
          className="flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-red-950/40 hover:text-red-300 hover:border-red-500/40 border border-slate-700 text-slate-300 transition-all disabled:opacity-50"
          title="Simulates a modified report payload to test tamper-detection engine"
        >
          <AlertTriangle size={13} className="text-amber-400" />
          Test Tamper Detection
        </button>
      </div>
    </div>
  );
};
