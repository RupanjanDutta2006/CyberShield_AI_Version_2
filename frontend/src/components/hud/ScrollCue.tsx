import React from 'react';

interface ScrollCueProps {
  visible: boolean;
  onScrollClick: () => void;
}

export const ScrollCue: React.FC<ScrollCueProps> = ({ visible, onScrollClick }) => {
  return (
    <button
      onClick={onScrollClick}
      className={`fixed bottom-6 left-1/2 -translate-x-1/2 z-20 flex flex-col items-center gap-2 font-mono text-[11px] tracking-widest text-slate-400 hover:text-white uppercase transition-all duration-500 cursor-pointer ${
        visible ? 'opacity-90 translate-y-0' : 'opacity-0 translate-y-4 pointer-events-none'
      }`}
      aria-label="Scroll to next chapter"
    >
      <span>Scroll</span>
      <div className="w-[1.5px] h-6 bg-slate-800 rounded-full overflow-hidden relative">
        <div className="w-full h-2.5 bg-red-500 rounded-full animate-bounce" />
      </div>
    </button>
  );
};
