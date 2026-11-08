import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowUpRight, ShieldAlert, Globe, FileText, Link2 } from 'lucide-react';

export interface CapabilityItem {
  id: string;
  indexStr: string;
  title: string;
  category: string;
  description: string;
  route: string;
  videoUrl: string;
  tag: string;
}

interface CapabilityCardProps {
  item: CapabilityItem;
  isActive: boolean;
  onSelect: () => void;
}

export const CapabilityCard: React.FC<CapabilityCardProps> = ({ item, isActive, onSelect }) => {
  const navigate = useNavigate();
  const [videoError, setVideoError] = useState(false);

  const getIcon = () => {
    switch (item.id) {
      case 'message':
        return <ShieldAlert className="w-4 h-4 text-[#AA88FF]" />;
      case 'url':
        return <Globe className="w-4 h-4 text-cyan-400" />;
      case 'evidence':
        return <FileText className="w-4 h-4 text-emerald-400" />;
      case 'trust':
        return <Link2 className="w-4 h-4 text-[#AA88FF]" />;
      default:
        return null;
    }
  };

  const handleAction = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigate(item.route);
  };

  return (
    <div
      onClick={onSelect}
      className={`group relative rounded-xl border p-3 transition-all duration-300 cursor-pointer overflow-hidden ${
        isActive
          ? 'border-[#AA88FF]/70 bg-[#141419]/90 shadow-[0_0_25px_rgba(170,136,255,0.18)]'
          : 'border-[#2A2A2A] bg-[#121212]/80 hover:border-[#444444] hover:bg-[#181818]/90'
      }`}
    >
      {/* Video Preview Container */}
      <div className="relative w-full h-36 rounded-lg overflow-hidden bg-black mb-3 border border-[#222222]">
        {!videoError ? (
          <video
            src={item.videoUrl}
            autoPlay
            muted
            loop
            playsInline
            preload="metadata"
            onError={() => setVideoError(true)}
            className="w-full h-full object-cover transition-transform duration-500 group-hover:scale-105 opacity-90 group-hover:opacity-100"
          />
        ) : (
          <div className="w-full h-full flex flex-col items-center justify-center bg-[#0a0a0e] text-[#8A8A8A] p-4 text-center">
            {getIcon()}
            <span className="text-[10px] uppercase font-mono tracking-wider mt-2">
              {item.title}
            </span>
          </div>
        )}

        {/* Video Overlay Badge */}
        <div className="absolute top-2 left-2 flex items-center gap-1.5 px-2 py-0.5 rounded bg-black/80 backdrop-blur-md border border-[#333333] text-[9px] font-mono uppercase text-[#DDDDDD]">
          {getIcon()}
          <span>{item.category}</span>
        </div>

        {/* Index Pill */}
        <div className="absolute top-2 right-2 px-1.5 py-0.5 rounded bg-black/80 backdrop-blur-md border border-[#333333] text-[9px] font-mono font-bold text-[#AA88FF]">
          {item.indexStr}
        </div>
      </div>

      {/* Card Info */}
      <div className="flex items-start justify-between gap-2">
        <div>
          <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-[#DDDDDD] group-hover:text-white transition-colors">
            {item.title}
          </h3>
          <p className="font-mono text-[11px] text-[#8A8A8A] leading-relaxed mt-1 line-clamp-2">
            {item.description}
          </p>
        </div>

        {/* Navigate Action Button */}
        <button
          onClick={handleAction}
          className="p-1.5 rounded-lg border border-[#333333] bg-[#1C1C1C] hover:border-[#AA88FF] hover:bg-[#AA88FF]/10 text-[#8A8A8A] hover:text-[#AA88FF] transition-all cursor-pointer self-start"
          title={`Launch ${item.title}`}
          aria-label={`Launch ${item.title}`}
        >
          <ArrowUpRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
};
