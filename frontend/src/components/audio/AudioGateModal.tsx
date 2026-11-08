import React, { useState, useEffect } from 'react';
import { Volume2, VolumeX, Shield, Radio } from 'lucide-react';
import { cyberAudio } from './CyberShieldAudio';

interface AudioGateModalProps {
  onEnter: (soundEnabled: boolean) => void;
}

export const AudioGateModal: React.FC<AudioGateModalProps> = ({ onEnter }) => {
  const [isVisible, setIsVisible] = useState(false);
  const [progress, setProgress] = useState(0);
  const [isReady, setIsReady] = useState(false);

  useEffect(() => {
    // Check if the user already chose during this session
    const chosen = sessionStorage.getItem('cybershield_audio_chosen');
    if (chosen) {
      // Already decided this session
      setIsVisible(false);
      return;
    }

    setIsVisible(true);

    // Cinematic progress simulation (calibrating defense grid)
    let current = 0;
    const interval = setInterval(() => {
      current += Math.floor(Math.random() * 18) + 12;
      if (current >= 100) {
        current = 100;
        clearInterval(interval);
        setProgress(100);
        setTimeout(() => setIsReady(true), 150);
      } else {
        setProgress(current);
      }
    }, 60);

    return () => clearInterval(interval);
  }, []);

  const handleChoice = async (enableSound: boolean) => {
    sessionStorage.setItem('cybershield_audio_chosen', 'true');
    await cyberAudio.setMuted(!enableSound);
    setIsVisible(false);
    onEnter(enableSound);
  };

  if (!isVisible) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/95 backdrop-blur-xl transition-all duration-700 animate-fadeIn font-mono">
      {/* Background scanner aura */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(255,30,56,0.12)_0%,transparent_70%)] pointer-events-none" />

      <div className="relative z-10 w-full max-w-md mx-4 p-8 rounded-2xl border border-red-500/20 bg-slate-950/90 shadow-[0_0_60px_rgba(255,30,56,0.15)] flex flex-col items-center text-center">
        {/* Shield Icon with glowing ring */}
        <div className="relative mb-6">
          <div className="absolute -inset-3 rounded-full bg-red-600/20 blur-md animate-pulse" />
          <div className="relative w-16 h-16 rounded-full border border-red-500/40 bg-black flex items-center justify-center text-red-500">
            <Shield className="w-8 h-8 stroke-[1.5]" />
          </div>
        </div>

        {/* Status Kicker */}
        <div className="flex items-center gap-2 text-xs uppercase tracking-widest text-red-400 mb-2">
          <Radio className="w-3.5 h-3.5 animate-spin" />
          <span>Calibrating Neural Defense Grid</span>
        </div>

        <h2 className="text-xl font-bold text-white tracking-wide mb-1 font-sans">
          CYBERSHIELD AI
        </h2>
        <p className="text-xs text-slate-400 max-w-xs mb-6">
          Cinematic real-time threat detection and forensic digital trust experience.
        </p>

        {/* Progress Bar */}
        <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden mb-3 border border-slate-800">
          <div
            className="h-full bg-gradient-to-r from-red-600 to-rose-400 transition-all duration-150 ease-out"
            style={{ width: `${progress}%` }}
          />
        </div>

        <div className="text-[11px] text-slate-500 mb-8 flex justify-between w-full font-mono">
          <span>SYSTEM_READY</span>
          <span className="text-red-400">{String(progress).padStart(3, '0')}%</span>
        </div>

        {/* Action Choice Buttons */}
        <div className="w-full flex flex-col sm:flex-row gap-3">
          <button
            disabled={!isReady}
            onClick={() => handleChoice(true)}
            className={`flex-1 flex items-center justify-center gap-2.5 py-3 px-4 rounded-xl text-xs font-semibold uppercase tracking-wider transition-all duration-300 ${
              isReady
                ? 'bg-red-600 hover:bg-red-500 text-white shadow-[0_0_25px_rgba(255,30,56,0.5)] cursor-pointer'
                : 'bg-red-950/40 text-red-400/40 cursor-not-allowed'
            }`}
          >
            <Volume2 className="w-4 h-4" />
            <span>Enter with sound</span>
          </button>

          <button
            disabled={!isReady}
            onClick={() => handleChoice(false)}
            className={`flex-1 flex items-center justify-center gap-2.5 py-3 px-4 rounded-xl text-xs font-semibold uppercase tracking-wider transition-all duration-300 border ${
              isReady
                ? 'border-slate-800 hover:border-slate-700 bg-slate-900/60 hover:bg-slate-900 text-slate-300 hover:text-white cursor-pointer'
                : 'border-slate-900 bg-slate-950 text-slate-700 cursor-not-allowed'
            }`}
          >
            <VolumeX className="w-4 h-4 text-slate-500" />
            <span>Enter muted</span>
          </button>
        </div>

        <p className="mt-4 text-[10px] text-slate-600">
          Audio is procedural (Web Audio API) and can be toggled anytime from the top-right HUD.
        </p>
      </div>
    </div>
  );
};
