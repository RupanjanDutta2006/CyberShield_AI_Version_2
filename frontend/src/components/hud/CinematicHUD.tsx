import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, ArrowUpRight, ChevronLeft, ChevronRight, Menu } from 'lucide-react';
import { ChapterKeyframe } from '../3d/CameraChoreographer';
import { cyberAudio } from '../audio/CyberShieldAudio';
import { ChapterRail } from './ChapterRail';
import { ChapterIndexModal } from './ChapterIndexModal';
import { ScrollCue } from './ScrollCue';

interface CinematicHUDProps {
  currentChapter: ChapterKeyframe;
  scrollProgress: number;
  onSelectChapter: (index: number) => void;
  onNextChapter: () => void;
  onPrevChapter: () => void;
}

export const CinematicHUD: React.FC<CinematicHUDProps> = ({
  currentChapter,
  scrollProgress: _scrollProgress,
  onSelectChapter,
  onNextChapter,
  onPrevChapter,
}) => {
  const navigate = useNavigate();
  const [isAudioMuted, setIsAudioMuted] = useState(true);
  const [isIndexOpen, setIsIndexOpen] = useState(false);

  useEffect(() => {
    return cyberAudio.subscribe((muted) => setIsAudioMuted(muted));
  }, []);

  const handleSoundToggle = () => {
    cyberAudio.toggle();
  };

  const handleCtaClick = () => {
    if (currentChapter.ctaRoute.startsWith('/')) {
      navigate(currentChapter.ctaRoute);
    } else {
      onNextChapter();
    }
  };

  return (
    <div className="fixed inset-0 pointer-events-none z-10 flex flex-col justify-between p-6 md:p-10 font-sans select-none">
      {/* ================= TOP BAR ================= */}
      <header className="w-full flex items-center justify-between pointer-events-auto">
        {/* Top-Left: Brand Mark */}
        <button
          onClick={() => onSelectChapter(0)}
          className="group flex items-center gap-3 text-left cursor-pointer focus:outline-none"
          aria-label="Back to introduction"
        >
          <div className="relative w-8 h-8 rounded-lg border border-red-500/30 bg-black/80 flex items-center justify-center text-red-500 group-hover:border-red-500 transition-colors shadow-[0_0_15px_rgba(255,30,56,0.2)]">
            <Shield className="w-4 h-4 stroke-[1.8]" />
          </div>
          <div className="flex flex-col">
            <span className="text-xs font-bold tracking-widest text-white group-hover:text-red-400 transition-colors uppercase font-mono">
              CYBERSHIELD AI
            </span>
            <span className="text-[10px] text-slate-500 font-mono tracking-wider">
              DEFENSE GRID
            </span>
          </div>
        </button>

        {/* Top-Center: Chapter Counter */}
        <div
          className="flex items-center gap-1.5 font-mono text-xs tracking-widest text-slate-400 bg-black/40 backdrop-blur-md px-3.5 py-1.5 rounded-full border border-slate-800/80"
          aria-live="polite"
        >
          <span className="text-red-400 font-bold">{currentChapter.chapterNumber}</span>
          <span className="text-slate-600">/</span>
          <span>06</span>
        </div>

        {/* Top-Right: Sound & Index Controls */}
        <div className="flex items-center gap-3 font-mono text-xs">
          {/* Sound Toggle */}
          <button
            onClick={handleSoundToggle}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-full border transition-all duration-300 cursor-pointer ${
              !isAudioMuted
                ? 'border-red-500/50 bg-red-950/30 text-red-400 shadow-[0_0_15px_rgba(255,30,56,0.25)]'
                : 'border-slate-800 bg-black/50 text-slate-400 hover:text-white hover:border-slate-700'
            }`}
            aria-pressed={!isAudioMuted}
            aria-label="Toggle Sound"
          >
            {/* Animated Equalizer Waveform */}
            <div className="flex items-center gap-0.5 h-3">
              <span
                className={`w-[2px] bg-current rounded-full transition-all duration-200 ${
                  !isAudioMuted ? 'h-3 animate-pulse' : 'h-1'
                }`}
              />
              <span
                className={`w-[2px] bg-current rounded-full transition-all duration-200 ${
                  !isAudioMuted ? 'h-2 animate-bounce' : 'h-1'
                }`}
              />
              <span
                className={`w-[2px] bg-current rounded-full transition-all duration-200 ${
                  !isAudioMuted ? 'h-3.5 animate-pulse' : 'h-1'
                }`}
              />
            </div>
            <span>Sound</span>
            <span className={!isAudioMuted ? 'text-red-300 font-bold' : 'text-slate-500'}>
              {!isAudioMuted ? 'on' : 'off'}
            </span>
          </button>

          {/* Index Menu Toggle */}
          <button
            onClick={() => setIsIndexOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-slate-800 bg-black/50 text-slate-300 hover:text-white hover:border-slate-700 transition-colors cursor-pointer"
            aria-label="Open Chapter Index"
          >
            <Menu className="w-3.5 h-3.5" />
            <span>Index</span>
          </button>
        </div>
      </header>

      {/* ================= RIGHT RAIL ================= */}
      <div className="pointer-events-auto">
        <ChapterRail
          currentChapter={currentChapter.chapterIndex}
          onSelectChapter={onSelectChapter}
        />
      </div>

      {/* ================= BOTTOM CONTENT AREA ================= */}
      <footer className="w-full flex flex-col md:flex-row items-end md:items-end justify-between gap-6 pointer-events-auto">
        {/* Bottom-Left: Chapter Narrative & Forensic Stats */}
        <div className="max-w-xl text-left">
          {/* Chapter Kicker & Badge */}
          <div className="flex items-center gap-3 mb-2 font-mono text-[11px] uppercase tracking-widest">
            <span className="text-red-400 font-semibold">{currentChapter.kicker}</span>
            <span className="text-slate-700">&bull;</span>
            <div className="flex items-center gap-1.5 text-slate-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>DEFENSE MATRIX ONLINE</span>
            </div>
          </div>

          {/* Chapter Main Headline */}
          <h1 className="text-2xl sm:text-3xl md:text-4xl font-extrabold text-white tracking-tight leading-tight mb-3 font-sans">
            {currentChapter.headline}
          </h1>

          {/* Description */}
          <p className="text-xs sm:text-sm text-slate-400 leading-relaxed font-sans max-w-lg mb-4">
            {currentChapter.description}
          </p>

          {/* Forensic Telemetry Stats */}
          <div className="flex flex-wrap items-center gap-2 sm:gap-4 font-mono text-[10px]">
            {currentChapter.stats.map((s, idx) => (
              <div
                key={idx}
                className="px-2.5 py-1 rounded border border-slate-800/80 bg-black/40 text-slate-400 flex items-center gap-1.5"
              >
                <span className="text-slate-500">{s.label}:</span>
                <span className="text-slate-200 font-semibold">{s.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Center: Scroll Cue (Visible on desktop) */}
        <ScrollCue
          visible={currentChapter.chapterIndex < 6}
          onScrollClick={onNextChapter}
        />

        {/* Bottom-Right: Chapter Call To Action */}
        <div className="flex items-center gap-3 self-stretch md:self-end justify-between md:justify-end">
          {/* Chapter Prev / Next Arrows */}
          <div className="flex items-center gap-1 font-mono text-xs">
            <button
              disabled={currentChapter.chapterIndex <= 0}
              onClick={onPrevChapter}
              className="p-2.5 rounded-xl border border-slate-800 hover:border-slate-700 bg-black/50 text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors cursor-pointer"
              aria-label="Previous Chapter"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              disabled={currentChapter.chapterIndex >= 6}
              onClick={onNextChapter}
              className="p-2.5 rounded-xl border border-slate-800 hover:border-slate-700 bg-black/50 text-slate-400 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors cursor-pointer"
              aria-label="Next Chapter"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>

          {/* Action Button Pill */}
          <button
            onClick={handleCtaClick}
            className="flex items-center gap-2.5 px-5 py-3 rounded-full font-mono text-xs font-semibold uppercase tracking-wider text-white bg-red-600 hover:bg-red-500 active:scale-95 shadow-[0_0_25px_rgba(255,30,56,0.4)] transition-all duration-300 cursor-pointer"
          >
            <span>{currentChapter.ctaLabel}</span>
            <ArrowUpRight className="w-4 h-4" />
          </button>
        </div>
      </footer>

      {/* Index Modal Drawer */}
      <ChapterIndexModal
        isOpen={isIndexOpen}
        onClose={() => setIsIndexOpen(false)}
        onSelectChapter={onSelectChapter}
      />
    </div>
  );
};
