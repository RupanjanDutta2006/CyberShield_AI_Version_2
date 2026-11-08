import React from 'react';
import { Link } from 'react-router-dom';

interface ExperienceNavigationProps {
  activeCounterStr: string;
  selectedTag: string;
  onSelectTag: (tag: string) => void;
  categories: string[];
}

export const ExperienceNavigation: React.FC<ExperienceNavigationProps> = ({
  activeCounterStr,
  selectedTag,
  onSelectTag,
  categories,
}) => {
  return (
    <>
      {/* ================= TOP-LEFT: BRAND ================= */}
      <div className="fixed top-6 left-6 z-20 flex items-center gap-3 select-none pointer-events-auto">
        <Link to="/dashboard" className="flex items-center gap-3 group" title="Open Operational Dashboard">
          {/* Original 40x40 Minimalist SVG Shield Emblem */}
          <div className="w-10 h-10 rounded-lg border border-[#2A2A2A] bg-black flex items-center justify-center p-1.5 shadow-[0_0_15px_rgba(170,136,255,0.12)] group-hover:border-[#AA88FF]/50 transition-colors">
            <svg
              viewBox="0 0 40 40"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
              className="w-full h-full text-[#AA88FF]"
            >
              {/* Outer faceted geometric shield */}
              <polygon
                points="20,4 34,10 34,24 20,36 6,24 6,10"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinejoin="round"
                fill="none"
              />
              {/* Inner core node */}
              <circle cx="20" cy="18" r="4" fill="#AA88FF" fillOpacity="0.8" />
              {/* Vertical axis line */}
              <line x1="20" y1="10" x2="20" y2="30" stroke="#DDDDDD" strokeWidth="1.2" strokeDasharray="2 2" />
            </svg>
          </div>

          <div className="flex flex-col">
            <span className="font-mono text-xs font-bold uppercase tracking-widest text-[#DDDDDD] group-hover:text-white transition-colors">
              CYBERSHIELD AI
            </span>
            <span className="font-mono text-[10px] text-[#8A8A8A] tracking-wider uppercase">
              DIGITAL THREAT INTELLIGENCE
            </span>
          </div>
        </Link>
      </div>

      {/* ================= TOP-RIGHT: CIRCULAR COUNTER ================= */}
      <div className="fixed top-6 right-20 z-20 pointer-events-none hidden sm:flex items-center justify-center">
        <div className="w-11 h-11 rounded-full border border-[#2A2A2A] bg-black/60 backdrop-blur-md flex items-center justify-center font-mono text-xs font-bold text-[#DDDDDD] tracking-wider shadow-[0_0_20px_rgba(0,0,0,0.8)]">
          {activeCounterStr}
        </div>
      </div>

      {/* ================= LEFT: INTERACTIVE CATEGORY FILTER CHIPS ================= */}
      <div className="fixed top-24 left-6 z-20 max-w-[320px] hidden sm:flex flex-wrap gap-1.5 font-mono text-[11px] pointer-events-auto">
        {categories.map((tag) => {
          const isSelected = selectedTag.toLowerCase() === tag.toLowerCase();
          return (
            <button
              key={tag}
              onClick={() => onSelectTag(tag)}
              className={`px-2.5 py-1 rounded border uppercase tracking-wider transition-all duration-200 cursor-pointer ${
                isSelected
                  ? 'border-[#AA88FF] bg-[#AA88FF]/15 text-[#AA88FF] font-bold shadow-[0_0_10px_rgba(170,136,255,0.2)]'
                  : 'border-[#2A2A2A] bg-[#1C1C1C]/90 text-[#8A8A8A] hover:border-[#444444] hover:text-[#DDDDDD]'
              }`}
            >
              {tag}
            </button>
          );
        })}
      </div>
    </>
  );
};
