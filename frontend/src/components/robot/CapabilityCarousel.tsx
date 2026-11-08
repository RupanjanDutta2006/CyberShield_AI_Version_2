import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronLeft, ChevronRight, ArrowUpRight, ShieldCheck } from 'lucide-react';

interface FeatureTab {
  id: string;
  num: string;
  title: string;
  category: string;
  description: string;
  route: string;
}

const FEATURES: FeatureTab[] = [
  {
    id: 'msg-analysis',
    num: '01',
    title: 'AI Message Analysis',
    category: 'Communication Triage',
    description: 'Deep semantic inspection of suspicious SMS, WhatsApp, and emails with multi-tier LLM failover.',
    route: '/message-analyzer',
  },
  {
    id: 'phishing',
    num: '02',
    title: 'Phishing Detection',
    category: 'Credential Theft Defense',
    description: 'Identifies deceptive login forms, urgent pretexts, and brand impersonation before data entry.',
    route: '/message-analyzer',
  },
  {
    id: 'job-scams',
    num: '03',
    title: 'Job Scam Detection',
    category: 'Employment Fraud',
    description: 'Flags fake remote work, high-salary task scams, and deposit requirements in chat messages.',
    route: '/message-analyzer',
  },
  {
    id: 'payment-fraud',
    num: '04',
    title: 'Payment Fraud Detection',
    category: 'Financial Protection',
    description: 'Interrogates rogue UPI handles, fake electricity disconnection threats, and unauthorized transfer prompts.',
    route: '/message-analyzer',
  },
  {
    id: 'social-eng',
    num: '05',
    title: 'Social Engineering Analysis',
    category: 'Behavioral Psychology',
    description: 'Quantifies psychological urgency hooks, fear pretexts, and authority manipulation patterns.',
    route: '/message-analyzer',
  },
  {
    id: 'url-intel',
    num: '06',
    title: 'URL Intelligence',
    category: 'Attack Surface',
    description: 'Real-time blacklist interrogation (URLhaus + PhishTank) without fetching hostile payloads.',
    route: '/scanner',
  },
  {
    id: 'domain-investigation',
    num: '07',
    title: 'Domain Investigation',
    category: 'Infrastructure',
    description: 'Heuristic domain scoring for dangerous TLDs, punycode spoofing, and IP-literal hosting.',
    route: '/scanner',
  },
  {
    id: 'evidence-extraction',
    num: '08',
    title: 'Evidence Extraction',
    category: 'Forensic Grounding',
    description: 'EvidenceValidator guarantees verbatim quotation checks, isolating telephone numbers (+91) and URLs.',
    route: '/history',
  },
  {
    id: 'threat-reports',
    num: '09',
    title: 'Threat Reports',
    category: 'Structured Reporting',
    description: 'Generates standardized forensic audit logs with risk scores, telemetry, and remediation guidance.',
    route: '/history',
  },
  {
    id: 'blockchain-verify',
    num: '10',
    title: 'Blockchain Verification',
    category: 'Cryptographic Trust',
    description: 'RFC 8785 canonical JSON formatting and SHA-256 fingerprinting with decentralized Sepolia anchoring.',
    route: '/history',
  },
];

export const CapabilityCarousel: React.FC = () => {
  const navigate = useNavigate();
  const [activeIndex, setActiveIndex] = useState(0);
  const [isPaused, setIsPaused] = useState(false);

  useEffect(() => {
    if (isPaused) return;

    // Auto-advance every 2.4 seconds
    const interval = setInterval(() => {
      setActiveIndex((prev) => (prev + 1) % FEATURES.length);
    }, 2400);

    return () => clearInterval(interval);
  }, [isPaused]);

  const activeFeature = FEATURES[activeIndex];

  return (
    <div
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
      className="w-full max-w-xl p-6 rounded-3xl border border-[#dedad2] bg-[#fbf9f5]/90 backdrop-blur-xl shadow-[0_8px_32px_rgba(0,0,0,0.03)]"
    >
      {/* Top Header & Pagination */}
      <div className="flex items-center justify-between mb-4 pb-3 border-b border-[#e8e4dc]">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-[#ff5500]" />
          <span className="text-[11px] font-mono uppercase tracking-widest text-[#787570]">
            SECURITY CAPABILITY MATRIX ({activeFeature.num} / 10)
          </span>
        </div>

        {/* Carousel Controls */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setActiveIndex((prev) => (prev - 1 + FEATURES.length) % FEATURES.length)}
            className="p-1.5 rounded-lg border border-[#dedad2] bg-white hover:border-[#ff5500] text-[#787570] hover:text-[#ff5500] transition-colors cursor-pointer"
            aria-label="Previous Feature"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <button
            onClick={() => setActiveIndex((prev) => (prev + 1) % FEATURES.length)}
            className="p-1.5 rounded-lg border border-[#dedad2] bg-white hover:border-[#ff5500] text-[#787570] hover:text-[#ff5500] transition-colors cursor-pointer"
            aria-label="Next Feature"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Feature Content */}
      <div className="min-h-[110px] flex flex-col justify-center">
        <div className="text-[10px] font-mono uppercase tracking-wider text-[#ff5500] mb-1 font-bold">
          {activeFeature.category}
        </div>
        <h3 className="text-xl font-bold text-[#141416] tracking-tight mb-2">
          {activeFeature.title}
        </h3>
        <p className="text-xs text-[#555558] leading-relaxed">
          {activeFeature.description}
        </p>
      </div>

      {/* Action Button & Indicator Pills */}
      <div className="mt-5 pt-4 border-t border-[#e8e4dc] flex items-center justify-between gap-4">
        {/* Step indicator pills */}
        <div className="flex items-center gap-1">
          {FEATURES.map((_, i) => (
            <button
              key={i}
              onClick={() => setActiveIndex(i)}
              className={`h-1.5 rounded-full transition-all duration-300 ${
                i === activeIndex ? 'w-5 bg-[#ff5500]' : 'w-1.5 bg-[#dedad2] hover:bg-[#b0aca4]'
              }`}
              aria-label={`Jump to feature ${i + 1}`}
            />
          ))}
        </div>

        <button
          onClick={() => navigate(activeFeature.route)}
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl border border-[#dedad2] bg-white hover:bg-[#ff5500] text-xs font-semibold text-[#141416] hover:text-white transition-all shadow-sm cursor-pointer group"
        >
          <span>Open Tool</span>
          <ArrowUpRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
        </button>
      </div>
    </div>
  );
};
