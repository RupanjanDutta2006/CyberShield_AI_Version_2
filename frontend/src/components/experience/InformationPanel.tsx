import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowUpRight } from 'lucide-react';

export const InformationPanel: React.FC = () => {
  return (
    <aside className="fixed right-6 lg:right-20 top-24 lg:top-1/2 lg:-translate-y-1/2 z-20 w-80 lg:w-96 flex flex-col gap-6 font-mono pointer-events-auto bg-black/40 lg:bg-transparent backdrop-blur-md lg:backdrop-blur-none p-4 lg:p-0 rounded-xl border border-[#222222] lg:border-none">
      {/* BLOCK 01 — INTELLIGENCE */}
      <div>
        <h4 className="text-[11px] font-bold uppercase tracking-widest text-[#AA88FF] mb-1.5">
          [INTELLIGENCE]
        </h4>
        <p className="text-xs text-[#DDDDDD] leading-relaxed">
          CyberShield AI brings message intelligence, URL investigation and digital trust into one focused security experience.
        </p>
      </div>

      {/* BLOCK 02 — MISSION */}
      <div>
        <h4 className="text-[11px] font-bold uppercase tracking-widest text-[#AA88FF] mb-1.5">
          [MISSION]
        </h4>
        <p className="text-xs text-[#8A8A8A] leading-relaxed">
          Suspicious signals rarely appear in isolation. CyberShield helps examine the evidence, connect relevant indicators and understand the security context behind digital threats.
        </p>
      </div>

      {/* BLOCK 03 — CAPABILITIES */}
      <div>
        <h4 className="text-[11px] font-bold uppercase tracking-widest text-[#AA88FF] mb-2">
          [EXPLORING]
        </h4>
        <ul className="text-xs text-[#DDDDDD] space-y-1">
          <li className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#AA88FF]" />
            <span>Scam message analysis</span>
          </li>
          <li className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            <span>URL and domain intelligence</span>
          </li>
          <li className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span>Evidence extraction</span>
          </li>
          <li className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
            <span>Risk assessment</span>
          </li>
          <li className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-white" />
            <span>Report integrity (RFC 8785)</span>
          </li>
          <li className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#AA88FF]" />
            <span>Blockchain verification</span>
          </li>
        </ul>
      </div>

      {/* BLOCK 04 — PLATFORM */}
      <div className="pt-2 border-t border-[#2A2A2A]">
        <h4 className="text-[11px] font-bold uppercase tracking-widest text-[#AA88FF] mb-2">
          [PLATFORM]
        </h4>
        <div className="grid grid-cols-2 gap-2 text-[11px] mb-3">
          <Link
            to="/message-analyzer"
            className="flex items-center justify-between text-[#8A8A8A] hover:text-[#AA88FF] py-1 transition-colors"
          >
            <span>Message Analysis</span>
            <ArrowUpRight className="w-3 h-3" />
          </Link>
          <Link
            to="/scanner"
            className="flex items-center justify-between text-[#8A8A8A] hover:text-[#AA88FF] py-1 transition-colors"
          >
            <span>URL Intelligence</span>
            <ArrowUpRight className="w-3 h-3" />
          </Link>
          <Link
            to="/history"
            className="flex items-center justify-between text-[#8A8A8A] hover:text-[#AA88FF] py-1 transition-colors"
          >
            <span>Threat Reports</span>
            <ArrowUpRight className="w-3 h-3" />
          </Link>
          <Link
            to="/history"
            className="flex items-center justify-between text-[#8A8A8A] hover:text-[#AA88FF] py-1 transition-colors"
          >
            <span>Digital Trust</span>
            <ArrowUpRight className="w-3 h-3" />
          </Link>
        </div>

        {/* Primary Operational Dashboard Button */}
        <Link
          to="/dashboard"
          className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg border border-[#AA88FF]/40 bg-[#1C1C1C] hover:bg-[#AA88FF]/15 text-xs font-bold uppercase tracking-wider text-[#DDDDDD] hover:text-white transition-all shadow-[0_0_15px_rgba(170,136,255,0.15)]"
        >
          <span>Launch Dashboard</span>
          <ArrowUpRight className="w-3.5 h-3.5 text-[#AA88FF]" />
        </Link>
      </div>
    </aside>
  );
};
