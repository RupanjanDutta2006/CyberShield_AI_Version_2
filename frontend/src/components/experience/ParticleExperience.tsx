import React, { useState, useEffect, useRef } from 'react';
import { ParticleSceneEngine } from './ParticleScene';
import { ExperienceFallback } from './ExperienceFallback';
import { ExperienceNavigation } from './ExperienceNavigation';
import { CapabilityCard, CapabilityItem } from './CapabilityCard';
import { InformationPanel } from './InformationPanel';
import { SoundToggle } from './SoundToggle';

const CAPABILITIES: CapabilityItem[] = [
  {
    id: 'message',
    indexStr: '01 / 04',
    title: 'Signal / Message',
    category: 'Communication Intelligence',
    description: 'AI-powered scam, phishing, and social engineering threat analysis with multi-provider failover.',
    route: '/message-analyzer',
    videoUrl: 'https://pub-86dc5b5484314368ac5436a674b0d919.r2.dev/aaaf/oraciteslArea.mp4',
    tag: 'Messages',
  },
  {
    id: 'url',
    indexStr: '02 / 04',
    title: 'Surface / URL',
    category: 'Attack Surface Inspection',
    description: 'Domain and suspicious-link investigation, safe defanging, and live blacklists (URLhaus + PhishTank).',
    route: '/scanner',
    videoUrl: 'https://pub-86dc5b5484314368ac5436a674b0d919.r2.dev/aaaf/facet-glass-hero.mp4',
    tag: 'URLs',
  },
  {
    id: 'evidence',
    indexStr: '03 / 04',
    title: 'Evidence / Report',
    category: 'Forensic Extraction',
    description: 'Structured threat findings, verbatim quote grounding, and passive telephone/domain indicators.',
    route: '/history',
    videoUrl: 'https://pub-86dc5b5484314368ac5436a674b0d919.r2.dev/aaaf/stellarmind-hero.mp4',
    tag: 'Evidence',
  },
  {
    id: 'trust',
    indexStr: '04 / 04',
    title: 'Trust / Ledger',
    category: 'Verifiable Integrity',
    description: 'RFC 8785 canonical report hashing, SHA-256 fingerprinting, and Sepolia blockchain proof registration.',
    route: '/history',
    videoUrl: 'https://pub-86dc5b5484314368ac5436a674b0d919.r2.dev/aaaf/thedropthroughArea.mp4',
    tag: 'Blockchain',
  },
];

const CATEGORIES = [
  'All',
  'Messages',
  'URLs',
  'Domains',
  'AI',
  'Evidence',
  'Reports',
  'Blockchain',
  'Verification',
  'Security',
];

export const ParticleExperience: React.FC = () => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const sceneRef = useRef<ParticleSceneEngine | null>(null);
  const [isSupported, setIsSupported] = useState(true);

  const [activeIndex, setActiveIndex] = useState(0);
  const [selectedTag, setSelectedTag] = useState('All');

  useEffect(() => {
    // Check WebGL support
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) {
        setIsSupported(false);
        return;
      }
    } catch {
      setIsSupported(false);
      return;
    }

    const container = containerRef.current;
    if (!container) return;

    try {
      const scene = new ParticleSceneEngine(container);
      sceneRef.current = scene;
    } catch {
      setIsSupported(false);
    }

    return () => {
      if (sceneRef.current) {
        sceneRef.current.dispose();
        sceneRef.current = null;
      }
    };
  }, []);

  // Filter capability cards based on active tag
  const filteredCapabilities = CAPABILITIES.filter((c) => {
    if (selectedTag === 'All') return true;
    const tagLower = selectedTag.toLowerCase();
    return (
      c.tag.toLowerCase().includes(tagLower) ||
      c.title.toLowerCase().includes(tagLower) ||
      c.category.toLowerCase().includes(tagLower) ||
      (tagLower === 'ai' && c.id === 'message') ||
      (tagLower === 'domains' && c.id === 'url') ||
      (tagLower === 'reports' && c.id === 'evidence') ||
      (tagLower === 'verification' && c.id === 'trust') ||
      (tagLower === 'security' && true)
    );
  });

  const activeItem = filteredCapabilities[activeIndex] || filteredCapabilities[0] || CAPABILITIES[0];

  const handleCardSelect = (idx: number) => {
    setActiveIndex(idx);
    // Send dynamic impulse to fluid simulation
    if (sceneRef.current) {
      sceneRef.current.fluid.splat(0.65, 0.5, (Math.random() - 0.5) * 0.05, (Math.random() - 0.5) * 0.05);
    }
  };

  return (
    <div className="relative w-screen h-screen overflow-hidden bg-black text-[#DDDDDD] font-mono select-none">
      {/* 1. WebGL 3D Canvas Container */}
      {isSupported ? (
        <div ref={containerRef} className="fixed inset-0 w-full h-full pointer-events-none z-0" />
      ) : (
        <ExperienceFallback />
      )}

      {/* 2. Top Navigation & Brand */}
      <ExperienceNavigation
        activeCounterStr={activeItem.indexStr}
        selectedTag={selectedTag}
        onSelectTag={(tag) => {
          setSelectedTag(tag);
          setActiveIndex(0);
        }}
        categories={CATEGORIES}
      />

      {/* 3. Audio Sound Toggle */}
      <SoundToggle />

      {/* 4. Left Video Cards List (Internally Scrollable, Top 240px, Width 320px) */}
      <div className="fixed top-36 left-6 bottom-6 z-20 w-[320px] hidden md:flex flex-col pointer-events-auto">
        <div className="flex items-center justify-between pb-2 mb-2 border-b border-[#2A2A2A] text-[10px] text-[#8A8A8A] uppercase tracking-wider">
          <span>CAPABILITIES ({filteredCapabilities.length})</span>
          <span className="text-[#AA88FF]">ACTIVE: {activeItem.indexStr}</span>
        </div>

        <div className="flex-1 overflow-y-auto pr-1 space-y-3.5 scrollbar-thin scrollbar-thumb-[#2A2A2A] scrollbar-track-transparent">
          {filteredCapabilities.map((item, idx) => (
            <CapabilityCard
              key={item.id}
              item={item}
              isActive={idx === activeIndex}
              onSelect={() => handleCardSelect(idx)}
            />
          ))}
        </div>
      </div>

      {/* 5. Right Information Panel (4 Content Blocks) */}
      <div className="hidden md:block">
        <InformationPanel />
      </div>

      {/* 6. Mobile Layout & Action Bar (< 768px) */}
      <div className="md:hidden fixed bottom-6 left-6 right-6 z-20 flex flex-col gap-3 pointer-events-auto">
        {/* Active Card Preview Pill */}
        <div className="p-4 rounded-xl border border-[#AA88FF]/40 bg-black/80 backdrop-blur-xl">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-[10px] text-[#AA88FF] uppercase tracking-wider font-bold">
              {activeItem.indexStr} &bull; {activeItem.category}
            </span>
          </div>
          <h3 className="text-sm font-bold text-white uppercase">{activeItem.title}</h3>
          <p className="text-[11px] text-[#8A8A8A] mt-1 line-clamp-2">{activeItem.description}</p>
        </div>

        {/* Quick Launch Button */}
        <div className="flex gap-2">
          <a
            href={activeItem.route}
            className="flex-1 py-3 px-4 rounded-xl border border-[#AA88FF] bg-[#AA88FF]/20 text-center text-xs font-bold uppercase tracking-wider text-white"
          >
            Launch Tool
          </a>
          <a
            href="/dashboard"
            className="py-3 px-4 rounded-xl border border-[#2A2A2A] bg-[#1C1C1C] text-center text-xs font-bold uppercase tracking-wider text-[#DDDDDD]"
          >
            Dashboard
          </a>
        </div>
      </div>
    </div>
  );
};
