import React from 'react';

interface SectionIndicatorProps {
  activeSection: number;
  onSelectSection: (index: number) => void;
}

export const SectionIndicator: React.FC<SectionIndicatorProps> = ({
  activeSection,
  onSelectSection,
}) => {
  const sections = [
    { index: 0, num: '01', label: 'INTRO' },
    { index: 1, num: '02', label: 'PRODUCT' },
    { index: 2, num: '03', label: 'TRUST' },
  ];

  return (
    <nav
      className="fixed right-8 top-1/2 -translate-y-1/2 z-30 hidden md:flex flex-col gap-5 font-mono text-[11px]"
      aria-label="Section Indicator"
    >
      {sections.map((s) => {
        const isActive = activeSection === s.index;
        return (
          <button
            key={s.index}
            onClick={() => onSelectSection(s.index)}
            className={`group flex items-center justify-end gap-3 transition-colors cursor-pointer text-right ${
              isActive ? 'text-[#141416] font-bold' : 'text-[#888884] hover:text-[#141416]'
            }`}
          >
            <span
              className={`tracking-widest transition-opacity duration-200 ${
                isActive ? 'opacity-100 text-[#ff5500]' : 'opacity-60 group-hover:opacity-100'
              }`}
            >
              {s.num} {s.label}
            </span>
            <div
              className={`w-2.5 h-2.5 rounded-full border transition-all duration-300 ${
                isActive
                  ? 'border-[#ff5500] bg-[#ff5500] scale-125 shadow-[0_0_8px_rgba(255,85,0,0.4)]'
                  : 'border-[#dedad2] bg-white group-hover:border-[#b0aca4]'
              }`}
            />
          </button>
        );
      })}
    </nav>
  );
};
