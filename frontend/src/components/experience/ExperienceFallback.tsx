import React, { useEffect, useRef } from 'react';

export const ExperienceFallback: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animId = 0;
    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    // Particle nodes for 2D fallback vortex
    const count = 1200;
    const particles = Array.from({ length: count }, (_, i) => {
      const u = (i / count) * Math.PI * 2 * 6;
      const baseR = 120 + Math.random() * 80;
      return {
        u,
        baseR,
        r: baseR,
        speed: 0.008 + Math.random() * 0.006,
        size: Math.random() * 1.8 + 0.6,
        isLavender: Math.random() > 0.88,
      };
    });

    let mouseX = window.innerWidth / 2;
    let mouseY = window.innerHeight / 2;

    const handlePointer = (e: MouseEvent) => {
      mouseX = e.clientX;
      mouseY = e.clientY;
    };
    window.addEventListener('mousemove', handlePointer);

    const render = () => {
      ctx.fillStyle = '#000000';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      const cx = canvas.width * 0.62;
      const cy = canvas.height * 0.5;

      particles.forEach((p) => {
        p.u += p.speed;
        const x = cx + Math.cos(p.u) * p.r;
        const y = cy + Math.sin(p.u) * (p.r * 1.25) - 0.2 * Math.abs(x - cx);

        // Mouse disturbance
        const dx = x - mouseX;
        const dy = y - mouseY;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 100) {
          p.r += (100 - dist) * 0.05;
        } else {
          p.r += (p.baseR - p.r) * 0.05;
        }

        ctx.beginPath();
        ctx.arc(x, y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = p.isLavender ? 'rgba(170, 136, 255, 0.85)' : 'rgba(220, 220, 230, 0.65)';
        ctx.fill();
      });

      animId = requestAnimationFrame(render);
    };
    render();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', resize);
      window.removeEventListener('mousemove', handlePointer);
    };
  }, []);

  return <canvas ref={canvasRef} className="fixed inset-0 w-full h-full pointer-events-none z-0" />;
};
