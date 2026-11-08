import React from 'react';
import { X, ArrowRight, Shield } from 'lucide-react';
import { CHAPTERS } from '../3d/CameraChoreographer';

interface ChapterIndexModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectChapter: (index: number) => void;
}

export const ChapterIndexModal: React.FC<ChapterIndexModalProps> = ({
  isOpen,
  onClose,
  onSelectChapter,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/95 backdrop-blur-2xl animate-fadeIn font-mono p-6">
      <div className="relative w-full max-w-4xl h-[85vh] flex flex-col justify-between">
        {/* Header */}
        <div className="flex items-center justify-between pb-6 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-red-500" />
            <span className="text-sm tracking-widest text-slate-300 uppercase">
              CHAPTER INDEX &bull; CYBERSHIELD DEFENSE MATRIX
            </span>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg border border-slate-800 hover:border-slate-700 bg-slate-900/60 text-slate-400 hover:text-white transition-colors cursor-pointer"
            aria-label="Close Index"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Chapters List */}
        <div className="flex-1 overflow-y-auto py-8 space-y-4">
          {CHAPTERS.map((ch) => (
            <div
              key={ch.chapterIndex}
              onClick={() => {
                onSelectChapter(ch.chapterIndex);
                onClose();
              }}
              className="group p-5 rounded-xl border border-slate-900 hover:border-red-500/40 bg-slate-950/60 hover:bg-red-950/20 transition-all duration-300 flex flex-col md:flex-row md:items-center justify-between gap-4 cursor-pointer"
            >
              <div className="flex items-start gap-5">
                <span className="text-xl font-bold text-red-500 font-mono">
                  {ch.chapterNumber}
                </span>
                <div>
                  <div className="text-[10px] uppercase tracking-widest text-red-400 mb-1">
                    {ch.kicker}
                  </div>
                  <h3 className="text-lg font-bold text-white group-hover:text-red-400 transition-colors font-sans">
                    {ch.title}
                  </h3>
                  <p className="text-xs text-slate-400 max-w-xl mt-1 font-sans">
                    {ch.description}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-3 self-end md:self-center">
                <span className="text-xs text-slate-500 group-hover:text-white font-mono uppercase tracking-wider">
                  Jump to Chapter
                </span>
                <div className="w-8 h-8 rounded-full border border-slate-800 group-hover:border-red-500/60 flex items-center justify-center text-slate-400 group-hover:text-red-400 group-hover:translate-x-1 transition-all">
                  <ArrowRight className="w-4 h-4" />
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="pt-4 border-t border-slate-900 flex justify-between items-center text-xs text-slate-600">
          <span>RFC 8785 CANONICAL SHA-256 VERIFIED</span>
          <span>SELECT CHAPTER TO INITIALIZE 3D CHOREOGRAPHY</span>
        </div>
      </div>
    </div>
  );
};
