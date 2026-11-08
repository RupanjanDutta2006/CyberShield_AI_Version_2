import React, { useEffect, useRef, useState } from 'react';
import { CyberShieldSceneEngine } from './CyberShieldScene';
import { WebGLFallback } from './WebGLFallback';

interface ThreeHeroCanvasProps {
  scrollProgress: number; // 0.0 to 6.0
}

function checkWebGLSupport(): boolean {
  try {
    const canvas = document.createElement('canvas');
    return !!(
      window.WebGLRenderingContext &&
      (canvas.getContext('webgl') || canvas.getContext('experimental-webgl'))
    );
  } catch {
    return false;
  }
}

export const ThreeHeroCanvas: React.FC<ThreeHeroCanvasProps> = ({ scrollProgress }) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const sceneEngineRef = useRef<CyberShieldSceneEngine | null>(null);
  const [isSupported, setIsSupported] = useState<boolean>(true);

  useEffect(() => {
    if (!checkWebGLSupport()) {
      setIsSupported(false);
      return;
    }

    const container = containerRef.current;
    if (!container) return;

    try {
      const engine = new CyberShieldSceneEngine(container);
      sceneEngineRef.current = engine;
    } catch {
      setIsSupported(false);
    }

    return () => {
      if (sceneEngineRef.current) {
        sceneEngineRef.current.destroy();
        sceneEngineRef.current = null;
      }
    };
  }, []);

  // Update scroll progress inside the 3D scene engine
  useEffect(() => {
    if (sceneEngineRef.current) {
      sceneEngineRef.current.setScrollProgress(scrollProgress);
    }
  }, [scrollProgress]);

  if (!isSupported) {
    return <WebGLFallback scrollProgress={scrollProgress} />;
  }

  return (
    <div
      ref={containerRef}
      className="fixed inset-0 w-full h-full pointer-events-none z-0 overflow-hidden bg-[#030305]"
    />
  );
};
