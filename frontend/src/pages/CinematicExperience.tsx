import React, { useState, useEffect, useRef, useCallback } from 'react';
import { ThreeHeroCanvas } from '../components/3d/ThreeHeroCanvas';
import { CHAPTERS, ChapterKeyframe } from '../components/3d/CameraChoreographer';
import { CinematicHUD } from '../components/hud/CinematicHUD';
import { CustomCursor } from '../components/hud/CustomCursor';
import { AudioGateModal } from '../components/audio/AudioGateModal';

export const CinematicExperience: React.FC = () => {
  const [scrollProgress, setScrollProgress] = useState<number>(0);
  const [currentChapter, setCurrentChapter] = useState<ChapterKeyframe>(CHAPTERS[0]);
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);

  // Sync scroll position with progress
  const handleScroll = useCallback(() => {
    const el = scrollContainerRef.current;
    if (!el) return;

    const scrollTop = el.scrollTop;
    const maxScroll = el.scrollHeight - el.clientHeight;
    if (maxScroll <= 0) return;

    // Map 0 to 1 scroll domain to 0.0 to 6.0 chapter domain
    const normalized = (scrollTop / maxScroll) * 6.0;
    setScrollProgress(normalized);

    const chapterIdx = Math.min(6, Math.max(0, Math.round(normalized)));
    setCurrentChapter(CHAPTERS[chapterIdx]);
  }, []);

  // Jump to specific chapter smoothly
  const jumpToChapter = useCallback((index: number) => {
    const el = scrollContainerRef.current;
    if (!el) return;

    const clamped = Math.max(0, Math.min(6, index));
    const maxScroll = el.scrollHeight - el.clientHeight;
    const targetScroll = (clamped / 6.0) * maxScroll;

    el.scrollTo({
      top: targetScroll,
      behavior: 'smooth',
    });
  }, []);

  const nextChapter = useCallback(() => {
    jumpToChapter(currentChapter.chapterIndex + 1);
  }, [currentChapter, jumpToChapter]);

  const prevChapter = useCallback(() => {
    jumpToChapter(currentChapter.chapterIndex - 1);
  }, [currentChapter, jumpToChapter]);

  // Keyboard navigation (Arrow keys & Page up/down)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'ArrowDown' || e.key === 'PageDown' || e.key === ' ') {
        e.preventDefault();
        nextChapter();
      } else if (e.key === 'ArrowUp' || e.key === 'PageUp') {
        e.preventDefault();
        prevChapter();
      } else if (e.key >= '0' && e.key <= '6') {
        jumpToChapter(parseInt(e.key, 10));
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [nextChapter, prevChapter, jumpToChapter]);

  return (
    <div className="relative w-full h-screen overflow-hidden bg-[#030305] text-slate-100">
      {/* 1. Custom Interactive Trailing Cursor */}
      <CustomCursor />

      {/* 2. Opening Audio Choice Gate Modal */}
      <AudioGateModal onEnter={() => {}} />

      {/* 3. Three.js Cinematic 3D Scene */}
      <ThreeHeroCanvas scrollProgress={scrollProgress} />

      {/* 4. Cinematic Heads-Up Display (HUD) */}
      <CinematicHUD
        currentChapter={currentChapter}
        scrollProgress={scrollProgress}
        onSelectChapter={jumpToChapter}
        onNextChapter={nextChapter}
        onPrevChapter={prevChapter}
      />

      {/* 5. Virtual Scroll Container (600vh height driving the journey) */}
      <div
        ref={scrollContainerRef}
        onScroll={handleScroll}
        className="absolute inset-0 z-0 h-full w-full overflow-y-auto scroll-smooth pointer-events-auto"
        style={{ scrollbarWidth: 'none', msOverflowStyle: 'none' }}
      >
        {/* Six 100vh stages */}
        <div className="h-screen w-full" data-chapter="0" />
        <div className="h-screen w-full" data-chapter="1" />
        <div className="h-screen w-full" data-chapter="2" />
        <div className="h-screen w-full" data-chapter="3" />
        <div className="h-screen w-full" data-chapter="4" />
        <div className="h-screen w-full" data-chapter="5" />
        <div className="h-screen w-full" data-chapter="6" />

        {/* Cinematic Finale Footer */}
        <footer className="relative z-10 w-full py-16 px-8 border-t border-slate-900 bg-black/90 backdrop-blur-2xl flex flex-col md:flex-row items-center justify-between gap-6 text-xs font-mono text-slate-500">
          <div className="flex flex-col gap-1 text-center md:text-left">
            <span className="text-white font-bold tracking-widest uppercase">
              CYBERSHIELD AI PLATFORM
            </span>
            <span>Autonomous Cyber Threat Triage & Digital Trust Infrastructure &bull; 2026</span>
          </div>

          <div className="flex items-center gap-6">
            <button
              onClick={() => jumpToChapter(0)}
              className="px-4 py-2 rounded-full border border-slate-800 hover:border-red-500/50 bg-slate-950 text-slate-300 hover:text-white transition-colors cursor-pointer"
            >
              Begin Again &uarr;
            </button>
          </div>
        </footer>
      </div>
    </div>
  );
};
