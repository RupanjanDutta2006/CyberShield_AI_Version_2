import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, X, ArrowUpRight, Volume2, VolumeX } from 'lucide-react';
import { cyberAudio } from '../audio/CyberShieldAudio';

interface NovaTopNavProps {
  onScrollToSection: (index: number) => void;
  scrollY: number;
}

export const NovaTopNav: React.FC<NovaTopNavProps> = ({ onScrollToSection, scrollY }) => {
  const navigate = useNavigate();
  const [isBannerVisible, setIsBannerVisible] = useState(true);
  const [isMuted, setIsMuted] = useState(true);

  useEffect(() => {
    return cyberAudio.subscribe((muted) => setIsMuted(muted));
  }, []);

  const handleSoundToggle = () => {
    cyberAudio.toggle();
  };

  const isBannerScrolledPast = scrollY > 40;

  return (
    <header className="fixed top-0 left-0 right-0 z-40 flex flex-col font-mono select-none">
      {/* 1. Dismissible Top Announcement Bar */}
      {isBannerVisible && (
        <div
          className={`w-full bg-[#18181a] text-white py-2 px-4 text-[11px] flex items-center justify-between transition-transform duration-300 ${
            isBannerScrolledPast ? '-translate-y-full opacity-0 pointer-events-none' : 'translate-y-0 opacity-100'
          }`}
        >
          <div className="flex-1 text-center">
            <Link
              to="/dashboard"
              className="inline-flex items-center gap-1.5 hover:text-[#ff7733] transition-colors"
            >
              <span>New: Explore the CyberShield Intelligence Platform</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </Link>
          </div>
          <button
            onClick={() => setIsBannerVisible(false)}
            className="p-1 hover:text-red-400 transition-colors cursor-pointer"
            aria-label="Dismiss Announcement"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* 2. Main Navigation Bar (52px tall, paper-white blur) */}
      <div className="w-full h-14 bg-[#efece6]/90 backdrop-blur-md border-b border-[#dedad2] px-6 sm:px-10 flex items-center justify-between">
        {/* Left: Brand */}
        <Link to="/" className="flex items-center gap-2.5 group">
          <div className="w-8 h-8 rounded-lg border border-[#d8d4cc] bg-white flex items-center justify-center text-[#ff5500] shadow-sm group-hover:border-[#ff5500] transition-colors">
            <Shield className="w-4 h-4" />
          </div>
          <span className="font-bold text-xs tracking-widest text-[#141416] uppercase">
            CYBERSHIELD AI
          </span>
        </Link>

        {/* Center: Section Links */}
        <nav className="hidden md:flex items-center gap-8 text-xs text-[#555558]">
          <button
            onClick={() => onScrollToSection(0)}
            className="hover:text-[#141416] transition-colors cursor-pointer"
          >
            Platform
          </button>
          <button
            onClick={() => onScrollToSection(1)}
            className="hover:text-[#141416] transition-colors cursor-pointer"
          >
            Capabilities
          </button>
          <button
            onClick={() => onScrollToSection(2)}
            className="hover:text-[#141416] transition-colors cursor-pointer"
          >
            Trust
          </button>
          <Link to="/settings" className="hover:text-[#141416] transition-colors">
            Insights
          </Link>
        </nav>

        {/* Right: Sound Toggle + Console Button */}
        <div className="flex items-center gap-3">
          {/* Ambient Sound Toggle */}
          <button
            onClick={handleSoundToggle}
            className={`p-2 rounded-lg border text-xs transition-colors cursor-pointer ${
              !isMuted
                ? 'border-[#ff5500] bg-[#ff5500]/10 text-[#ff5500]'
                : 'border-[#dedad2] bg-white text-[#787570] hover:text-[#141416]'
            }`}
            title="Toggle Ambient Audio"
            aria-label="Toggle Ambient Audio"
          >
            {!isMuted ? <Volume2 className="w-3.5 h-3.5" /> : <VolumeX className="w-3.5 h-3.5" />}
          </button>

          {/* Primary Action Button */}
          <button
            onClick={() => navigate('/dashboard')}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg border border-[#141416] bg-[#141416] hover:bg-[#ff5500] hover:border-[#ff5500] text-white text-xs font-semibold uppercase tracking-wider transition-all shadow-sm cursor-pointer"
          >
            <span>Open Security Console</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </header>
  );
};
