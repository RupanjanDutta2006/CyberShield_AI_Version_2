import React, { useState, useEffect } from 'react';
import { cyberAudio } from '../audio/CyberShieldAudio';

export const SoundToggle: React.FC = () => {
  const [isMuted, setIsMuted] = useState(true);

  useEffect(() => {
    return cyberAudio.subscribe((muted) => setIsMuted(muted));
  }, []);

  const handleToggle = () => {
    cyberAudio.toggle();
  };

  return (
    <button
      onClick={handleToggle}
      className={`fixed top-6 right-6 z-20 flex items-center gap-2 px-3 py-1.5 rounded-full border font-mono text-[11px] tracking-wider uppercase transition-all duration-300 cursor-pointer pointer-events-auto ${
        !isMuted
          ? 'border-[#AA88FF] bg-[#AA88FF]/15 text-[#AA88FF] shadow-[0_0_15px_rgba(170,136,255,0.25)]'
          : 'border-[#2A2A2A] bg-black/60 text-[#8A8A8A] hover:text-[#DDDDDD] hover:border-[#444444]'
      }`}
      aria-label="Toggle Ambient Audio"
      title="Toggle Ambient Audio (Procedural)"
    >
      <span className="flex items-center gap-0.5 h-2.5">
        <span
          className={`w-[1.5px] bg-current rounded-full transition-all duration-200 ${
            !isMuted ? 'h-2.5 animate-pulse' : 'h-1'
          }`}
        />
        <span
          className={`w-[1.5px] bg-current rounded-full transition-all duration-200 ${
            !isMuted ? 'h-1.5 animate-bounce' : 'h-1'
          }`}
        />
        <span
          className={`w-[1.5px] bg-current rounded-full transition-all duration-200 ${
            !isMuted ? 'h-3 animate-pulse' : 'h-1'
          }`}
        />
      </span>
      <span>SOUND:</span>
      <span className={!isMuted ? 'text-white font-bold' : 'text-[#8A8A8A]'}>
        {!isMuted ? 'ON' : 'OFF'}
      </span>
    </button>
  );
};
