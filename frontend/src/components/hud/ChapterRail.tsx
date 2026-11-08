import React from 'react';
import { CHAPTERS } from '../3d/CameraChoreographer';

interface ChapterRailProps {
  currentChapter: number;
  onSelectChapter: (index: number) => void;
}

export const ChapterRail: React.FC<ChapterRailProps> = ({ currentChapter, onSelectChapter }) => {
  // Exclude 00 from the rail, show 01 to 06
  const railChapters = CHAPTERS.filter((c) => c.chapterIndex > 0);

  return (
    <nav
      className="fixed right-6 md:right-10 top-1/2 -translate-y-1/2 z-20 hidden sm:flex flex-col gap-3 font-mono text-[11px]"
      aria-label="Chapter Navigation Rail"
    >
      {railChapters.map((ch) => {
        const isActive = currentChapter === ch.chapterIndex;
        return (
          <button
            key={ch.chapterIndex}
            onClick={() => onSelectChapter(ch.chapterIndex)}
            className={`group flex items-center justify-end gap-3 text-right py-1 px-2 rounded transition-all duration-300 cursor-pointer ${
              isActive ? 'text-white' : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            {/* Chapter title (visible on hover or active) */}
            <span
              className={`tracking-wider transition-all duration-300 ${
                isActive
                  ? 'opacity-100 font-medium translate-x-0'
                  : 'opacity-0 group-hover:opacity-100 translate-x-2 group-hover:translate-x-0'
              }`}
            >
              {ch.title}
            </span>

            {/* Chapter Number */}
            <span className={isActive ? 'text-red-400 font-bold' : 'group-hover:text-slate-300'}>
              {ch.chapterNumber}
            </span>

            {/* Glowing Active Pip */}
            <div
              className={`w-1.5 h-1.5 rounded-full transition-all duration-300 ${
                isActive
                  ? 'bg-red-500 scale-150 shadow-[0_0_8px_rgba(255,30,56,0.9)]'
                  : 'bg-slate-700 group-hover:bg-slate-400'
              }`}
            />
          </button>
        );
      })}
    </nav>
  );
};
