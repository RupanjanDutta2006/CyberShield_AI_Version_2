import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Sparkles, ArrowRight } from 'lucide-react';

const PROMPTS = [
  'Analyse this suspicious banking message.',
  'Inspect this URL for phishing indicators.',
  'Explain the evidence behind this risk assessment.',
  'Verify the integrity of this security report.',
];

export const PromptTyper: React.FC = () => {
  const navigate = useNavigate();
  const [promptIndex, setPromptIndex] = useState(0);
  const [displayText, setDisplayText] = useState('');
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    const currentFullPrompt = PROMPTS[promptIndex];
    let timer: ReturnType<typeof setTimeout>;

    if (!isDeleting) {
      if (displayText.length < currentFullPrompt.length) {
        // Typing forward (~38ms per character)
        timer = setTimeout(() => {
          setDisplayText(currentFullPrompt.slice(0, displayText.length + 1));
        }, 38);
      } else {
        // Finished typing; pause for 2.2 seconds
        timer = setTimeout(() => {
          setIsDeleting(true);
        }, 2200);
      }
    } else {
      if (displayText.length > 0) {
        // Deleting backward (~22ms per character)
        timer = setTimeout(() => {
          setDisplayText(currentFullPrompt.slice(0, displayText.length - 1));
        }, 22);
      } else {
        // Finished deleting; move to next prompt
        setIsDeleting(false);
        setPromptIndex((prev) => (prev + 1) % PROMPTS.length);
      }
    }

    return () => clearTimeout(timer);
  }, [displayText, isDeleting, promptIndex]);

  return (
    <div className="w-full max-w-md p-4 rounded-2xl border border-[#dedad2] bg-[#fbf9f5]/90 backdrop-blur-md shadow-[0_4px_24px_rgba(0,0,0,0.04)] font-mono">
      <div className="flex items-center justify-between mb-2 text-[10px] uppercase tracking-widest text-[#787570]">
        <div className="flex items-center gap-1.5">
          <Sparkles className="w-3.5 h-3.5 text-[#ff5500]" />
          <span>CYBERSHIELD AI PROMPT LAB</span>
        </div>
        <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
      </div>

      {/* Typing Display Box */}
      <div className="min-h-[52px] flex items-center bg-white px-3.5 py-2.5 rounded-xl border border-[#e8e4dc] text-xs text-[#1a1a1d] font-mono leading-relaxed mb-3">
        <span className="text-[#ff5500] font-bold mr-2">&gt;</span>
        <span>{displayText}</span>
        <span className="inline-block w-2 h-3.5 bg-[#ff5500] ml-1 animate-pulse" />
      </div>

      {/* Action Button */}
      <button
        onClick={() => navigate('/message-analyzer')}
        className="w-full flex items-center justify-between px-3.5 py-2 rounded-xl border border-[#dedad2] hover:border-[#ff5500] bg-[#f4f1ea] hover:bg-[#ff5500]/10 text-xs font-semibold text-[#1a1a1d] hover:text-[#ff5500] transition-all cursor-pointer group"
      >
        <span>Launch Real Message Analyzer</span>
        <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
      </button>
    </div>
  );
};
