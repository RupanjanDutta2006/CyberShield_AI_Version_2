import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { RobotSceneEngine } from './RobotScene';
import { NovaTopNav } from './NovaTopNav';
import { SectionIndicator } from './SectionIndicator';
import { PromptTyper } from './PromptTyper';
import { CapabilityCarousel } from './CapabilityCarousel';
import { ArrowUpRight, Shield, CheckCircle2, Lock, ArrowRight } from 'lucide-react';

export const CyberShieldExperience: React.FC = () => {
  const navigate = useNavigate();
  const canvasContainerRef = useRef<HTMLDivElement | null>(null);
  const sceneEngineRef = useRef<RobotSceneEngine | null>(null);

  const [activeSection, setActiveSection] = useState(0);
  const [scrollY, setScrollY] = useState(0);

  // Initialize Three.js Robot Scene
  useEffect(() => {
    const container = canvasContainerRef.current;
    if (!container) return;

    try {
      const scene = new RobotSceneEngine(container);
      sceneEngineRef.current = scene;
    } catch {
      // Graceful fallback
    }

    return () => {
      if (sceneEngineRef.current) {
        sceneEngineRef.current.dispose();
        sceneEngineRef.current = null;
      }
    };
  }, []);

  // Track window scroll position and interpolate camera
  const handleScroll = useCallback(() => {
    const y = window.scrollY;
    setScrollY(y);

    const vh = window.innerHeight;
    const progress = Math.max(0, Math.min(2, y / vh));

    if (sceneEngineRef.current) {
      sceneEngineRef.current.setScrollProgress(progress);
    }

    const currentIdx = Math.min(2, Math.round(progress));
    setActiveSection(currentIdx);
  }, []);

  useEffect(() => {
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, [handleScroll]);

  const scrollToSection = (index: number) => {
    const targetY = index * window.innerHeight;
    window.scrollTo({
      top: targetY,
      behavior: 'smooth',
    });
  };

  return (
    <div className="relative w-full min-h-[300vh] bg-[#efece6] text-[#141416] selection:bg-[#ff5500]/20 selection:text-[#141416]">
      {/* 1. Subtle Paper-White Architectural Grid Background */}
      <div
        className="fixed inset-0 pointer-events-none z-0"
        style={{
          backgroundImage:
            'linear-gradient(to right, rgba(220, 215, 205, 0.45) 1px, transparent 1px), linear-gradient(to bottom, rgba(220, 215, 205, 0.45) 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }}
      />

      {/* 2. Fixed WebGL Robot Canvas in Background */}
      <div
        ref={canvasContainerRef}
        className="fixed inset-0 w-full h-full pointer-events-none z-10 overflow-hidden"
      />

      {/* 3. Top Navigation */}
      <NovaTopNav onScrollToSection={scrollToSection} scrollY={scrollY} />

      {/* 4. Desktop Right-Side Section Rail */}
      <SectionIndicator activeSection={activeSection} onSelectSection={scrollToSection} />

      {/* =========================================================================
          SECTION 01 — INTRO / INTELLIGENCE (~100vh)
          ========================================================================= */}
      <section className="relative z-20 min-h-screen w-full flex flex-col justify-between px-6 sm:px-12 md:px-20 pt-28 pb-12">
        <div className="max-w-2xl mt-4">
          {/* Feature List Header */}
          <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-[#787570] uppercase tracking-wider mb-6">
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              <span>MESSAGE INTELLIGENCE</span>
            </span>
            <span>&bull;</span>
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-500" />
              <span>URL INVESTIGATION</span>
            </span>
            <span>&bull;</span>
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#ff5500]" />
              <span>THREAT ANALYSIS</span>
            </span>
            <span>&bull;</span>
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-purple-500" />
              <span>DIGITAL TRUST</span>
            </span>
          </div>

          {/* Hero Headline */}
          <h1 className="text-4xl sm:text-5xl md:text-6xl font-extrabold tracking-tight leading-[1.08] text-[#141416] mb-5 font-sans">
            Security with a little <br />
            <span className="underline decoration-[#ff5500]/40 decoration-wavy">more intelligence.</span>
          </h1>

          {/* Description */}
          <p className="text-base sm:text-lg text-[#555558] leading-relaxed max-w-xl mb-8 font-sans">
            Investigate suspicious messages, uncover dangerous links and understand digital threats through evidence-led AI intelligence.
          </p>

          {/* Primary Action Buttons */}
          <div className="flex flex-wrap items-center gap-4 mb-8">
            <button
              onClick={() => navigate('/message-analyzer')}
              className="flex items-center gap-2 px-6 py-3.5 rounded-full bg-[#141416] hover:bg-[#ff5500] text-white text-xs font-mono font-bold uppercase tracking-wider transition-all shadow-md cursor-pointer"
            >
              <span>Start an Investigation</span>
              <ArrowRight className="w-4 h-4" />
            </button>
            <button
              onClick={() => scrollToSection(1)}
              className="px-6 py-3.5 rounded-full border border-[#dedad2] bg-white/80 hover:bg-white text-xs font-mono font-semibold uppercase tracking-wider text-[#141416] hover:border-[#ff5500] transition-all cursor-pointer"
            >
              Explore Capabilities ↓
            </button>
          </div>

          {/* Animated Prompt Typer Box */}
          <PromptTyper />
        </div>

        {/* Section 01 Bottom Editorial Headline */}
        <div className="pt-8 border-t border-[#dedad2]/80 mt-12 flex flex-col sm:flex-row sm:items-end justify-between gap-4">
          <div className="font-sans font-black text-2xl sm:text-4xl md:text-5xl tracking-tighter text-[#141416]/90 uppercase leading-none">
            THINK BEFORE <br />
            <span className="text-[#ff5500]">THREATS SPREAD.</span>
          </div>
          <div className="font-mono text-[11px] text-[#787570] uppercase tracking-wider">
            RFC 8785 VERIFIABLE INTEGRITY &bull; 2026
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 02 — PRODUCT / CAPABILITIES (~100vh)
          ========================================================================= */}
      <section className="relative z-20 min-h-screen w-full flex flex-col justify-center px-6 sm:px-12 md:px-20 py-24">
        <div className="max-w-2xl mb-10">
          <div className="text-xs font-mono font-bold uppercase tracking-widest text-[#ff5500] mb-2">
            [SECTION 02 &bull; PRODUCT CAPABILITIES]
          </div>
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-extrabold tracking-tight text-[#141416] mb-4">
            Your Security Intelligence Layer.
          </h2>
          <p className="text-sm sm:text-base text-[#555558] leading-relaxed max-w-lg">
            From message analysis to verifiable digital evidence, CyberShield brings security investigations into one connected experience.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          {/* Left: 10-Feature Animated Capability Carousel */}
          <div className="lg:col-span-7">
            <CapabilityCarousel />
          </div>

          {/* Right: Three Main Product Panels */}
          <div className="lg:col-span-5 flex flex-col gap-4">
            {/* Panel 1 */}
            <div
              onClick={() => navigate('/message-analyzer')}
              className="p-5 rounded-2xl border border-[#dedad2] bg-[#fbf9f5]/90 hover:border-[#ff5500] hover:bg-white transition-all cursor-pointer group shadow-sm"
            >
              <div className="flex items-center justify-between mb-1">
                <h4 className="font-mono text-xs font-bold uppercase tracking-wider text-[#141416]">
                  MESSAGE INTELLIGENCE
                </h4>
                <ArrowUpRight className="w-4 h-4 text-[#787570] group-hover:text-[#ff5500] group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
              </div>
              <p className="text-xs text-[#555558]">
                Understand the signals behind suspicious messages with multi-tier LLM failover.
              </p>
            </div>

            {/* Panel 2 */}
            <div
              onClick={() => navigate('/scanner')}
              className="p-5 rounded-2xl border border-[#dedad2] bg-[#fbf9f5]/90 hover:border-[#ff5500] hover:bg-white transition-all cursor-pointer group shadow-sm"
            >
              <div className="flex items-center justify-between mb-1">
                <h4 className="font-mono text-xs font-bold uppercase tracking-wider text-[#141416]">
                  URL INTELLIGENCE
                </h4>
                <ArrowUpRight className="w-4 h-4 text-[#787570] group-hover:text-[#ff5500] group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
              </div>
              <p className="text-xs text-[#555558]">
                Look beyond a link and examine the available threat evidence safely without payload downloads.
              </p>
            </div>

            {/* Panel 3 */}
            <div
              onClick={() => navigate('/history')}
              className="p-5 rounded-2xl border border-[#dedad2] bg-[#fbf9f5]/90 hover:border-[#ff5500] hover:bg-white transition-all cursor-pointer group shadow-sm"
            >
              <div className="flex items-center justify-between mb-1">
                <h4 className="font-mono text-xs font-bold uppercase tracking-wider text-[#141416]">
                  DIGITAL TRUST
                </h4>
                <ArrowUpRight className="w-4 h-4 text-[#787570] group-hover:text-[#ff5500] group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
              </div>
              <p className="text-xs text-[#555558]">
                Preserve report integrity and verify what matters via cryptographic SHA-256 proofs.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 03 — TRUST / DIGITAL EVIDENCE (~100vh)
          ========================================================================= */}
      <section className="relative z-20 min-h-screen w-full flex flex-col justify-between px-6 sm:px-12 md:px-20 py-24 border-t border-[#dedad2]/80">
        <div className="max-w-2xl mt-8">
          <div className="text-xs font-mono font-bold uppercase tracking-widest text-[#ff5500] mb-3">
            [SECTION 03 &bull; TRUST & VERIFICATION]
          </div>
          {/* Main Statement */}
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-extrabold tracking-tight text-[#141416] leading-tight mb-4">
            “Evidence should speak louder than assumptions.”
          </h2>
          <p className="text-base text-[#555558] leading-relaxed max-w-xl mb-10">
            CyberShield AI aims to make threat assessments understandable, traceable and verifiable through structured analysis and digital evidence.
          </p>

          {/* Three Evidence Principles */}
          <div className="space-y-4 max-w-xl">
            <div className="p-4 rounded-xl border border-[#dedad2] bg-white/80 flex items-start gap-3.5">
              <CheckCircle2 className="w-5 h-5 text-[#ff5500] shrink-0 mt-0.5" />
              <div>
                <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-[#141416]">
                  01 — TRACEABLE ANALYSIS
                </h4>
                <p className="text-xs text-[#555558] mt-0.5">
                  AI findings include verbatim grounded quotes directly from the original submitted message.
                </p>
              </div>
            </div>

            <div className="p-4 rounded-xl border border-[#dedad2] bg-white/80 flex items-start gap-3.5">
              <Shield className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
              <div>
                <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-[#141416]">
                  02 — STRUCTURED REPORTS
                </h4>
                <p className="text-xs text-[#555558] mt-0.5">
                  Security findings are preserved in a standardized audit report with risk assessments and extracted indicators.
                </p>
              </div>
            </div>

            <div className="p-4 rounded-xl border border-[#dedad2] bg-white/80 flex items-start gap-3.5">
              <Lock className="w-5 h-5 text-purple-600 shrink-0 mt-0.5" />
              <div>
                <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-[#141416]">
                  03 — VERIFIABLE INTEGRITY
                </h4>
                <p className="text-xs text-[#555558] mt-0.5">
                  SHA-256 fingerprints and on-chain Ethereum Sepolia verification establish whether recorded reports remain unchanged.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Final CTA & Footer */}
        <div className="pt-12 border-t border-[#dedad2] mt-16">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-12">
            <div>
              <h3 className="text-2xl font-bold text-[#141416] tracking-tight mb-1">
                Your next investigation starts here.
              </h3>
              <p className="text-xs font-mono text-[#787570]">
                Access the real CyberShield AI threat analysis microservices.
              </p>
            </div>

            <div className="flex flex-wrap gap-3">
              <button
                onClick={() => navigate('/message-analyzer')}
                className="px-5 py-3 rounded-full bg-[#141416] hover:bg-[#ff5500] text-white text-xs font-mono font-bold uppercase tracking-wider transition-colors shadow-sm cursor-pointer"
              >
                Analyse a Message
              </button>
              <button
                onClick={() => navigate('/scanner')}
                className="px-5 py-3 rounded-full border border-[#dedad2] bg-white hover:border-[#141416] text-[#141416] text-xs font-mono font-bold uppercase tracking-wider transition-colors cursor-pointer"
              >
                Scan a URL
              </button>
            </div>
          </div>

          <footer className="flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono text-[#888884] pt-6 border-t border-[#dedad2]/60">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-[#ff5500]" />
              <span className="font-bold text-[#141416]">CYBERSHIELD AI</span>
              <span>&bull;</span>
              <span>Intelligence Before Impact &bull; 2026</span>
            </div>
            <div className="flex items-center gap-6">
              <button onClick={() => scrollToSection(0)} className="hover:text-[#141416] transition-colors">
                Back to Top &uarr;
              </button>
              <a href="/dashboard" className="hover:text-[#141416] transition-colors">
                Security Console
              </a>
            </div>
          </footer>
        </div>
      </section>
    </div>
  );
};
