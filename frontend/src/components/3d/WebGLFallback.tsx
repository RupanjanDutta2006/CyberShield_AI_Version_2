import React, { useEffect, useRef } from 'react';
import { Shield, AlertTriangle } from 'lucide-react';

interface WebGLFallbackProps {
  scrollProgress: number;
}

export const WebGLFallback: React.FC<WebGLFallbackProps> = ({ scrollProgress: _scrollProgress }) => {
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

    // Particle nodes
    const nodes = Array.from({ length: 65 }, () => ({
      x: Math.random() * window.innerWidth,
      y: Math.random() * window.innerHeight,
      vx: (Math.random() - 0.5) * 0.8,
      vy: (Math.random() - 0.5) * 0.8,
      size: Math.random() * 2.5 + 1,
    }));

    const render = () => {
      ctx.fillStyle = '#030305';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      const cx = canvas.width / 2;
      const cy = canvas.height / 2;

      // Draw red laser scanning cross
      ctx.strokeStyle = 'rgba(255, 30, 56, 0.65)';
      ctx.lineWidth = 1.5;
      ctx.shadowColor = '#ff1e38';
      ctx.shadowBlur = 20;

      ctx.beginPath();
      ctx.moveTo(0, cy);
      ctx.lineTo(canvas.width, cy);
      ctx.stroke();

      ctx.beginPath();
      ctx.moveTo(cx, 0);
      ctx.lineTo(cx, canvas.height);
      ctx.stroke();

      ctx.shadowBlur = 0;

      // Draw connecting cyber nodes
      ctx.fillStyle = 'rgba(255, 255, 255, 0.7)';
      nodes.forEach((n, i) => {
        n.x += n.vx;
        n.y += n.vy;
        if (n.x < 0 || n.x > canvas.width) n.vx *= -1;
        if (n.y < 0 || n.y > canvas.height) n.vy *= -1;

        ctx.beginPath();
        ctx.arc(n.x, n.y, n.size, 0, Math.PI * 2);
        ctx.fill();

        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[j].x - n.x;
          const dy = nodes[j].y - n.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 110) {
            ctx.strokeStyle = `rgba(255, 30, 56, ${0.2 * (1 - dist / 110)})`;
            ctx.lineWidth = 0.7;
            ctx.beginPath();
            ctx.moveTo(n.x, n.y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.stroke();
          }
        }
      });

      animId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return (
    <div className="absolute inset-0 w-full h-full bg-[#030305] overflow-hidden">
      <canvas ref={canvasRef} className="absolute inset-0 w-full h-full" />
      {/* Central 2D Shield */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <div className="relative animate-pulse">
          <div className="absolute -inset-6 rounded-full bg-red-600/20 blur-xl" />
          <div className="relative w-28 h-28 rounded-2xl border border-red-500/40 bg-slate-950/80 backdrop-blur-md flex items-center justify-center text-red-500 shadow-[0_0_50px_rgba(255,30,56,0.3)]">
            <Shield className="w-16 h-16 stroke-[1.2]" />
          </div>
        </div>
        <div className="mt-6 flex items-center gap-2 px-3 py-1 rounded-full bg-red-950/40 border border-red-500/20 text-[11px] text-red-400 font-mono">
          <AlertTriangle className="w-3.5 h-3.5" />
          <span>ACCELERATED 2D DEFENSE MATRIX ACTIVE</span>
        </div>
      </div>
    </div>
  );
};
