import React from 'react';
import { NavLink, Link } from 'react-router-dom';
import { Shield, Search, MessageSquare, History, Settings, Activity, Sparkles } from 'lucide-react';

export const Navbar: React.FC = () => {
  const navItems = [
    { name: 'Thinking Security', path: '/', icon: Sparkles, highlight: true },
    { name: 'Dashboard', path: '/dashboard', icon: Activity },
    { name: 'URL Scanner', path: '/scanner', icon: Search },
    { name: 'Message Analyzer', path: '/message-analyzer', icon: MessageSquare },
    { name: 'Scan History', path: '/history', icon: History },
    { name: 'System & APIs', path: '/settings', icon: Settings },
  ];

  return (
    <header className="sticky top-0 z-50 backdrop-blur-md bg-[#efece6]/90 border-b border-[#dedad2]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 font-mono">
          {/* Logo & Branding */}
          <Link to="/" className="flex items-center gap-2.5 group">
            <div className="w-9 h-9 rounded-xl border border-[#dedad2] bg-white flex items-center justify-center text-[#ff5500] shadow-sm group-hover:border-[#ff5500] transition-colors">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm tracking-tight text-[#141416] uppercase">
                  CyberShield AI
                </span>
                <span className="px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider rounded bg-[#ff5500]/15 text-[#ff5500] border border-[#ff5500]/30">
                  v2.0
                </span>
              </div>
              <p className="text-[10px] text-[#787570] font-medium hidden sm:block uppercase">
                Thinking Security Intelligence
              </p>
            </div>
          </Link>

          {/* Navigation Links */}
          <nav className="flex items-center gap-1 sm:gap-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  end={item.path === '/'}
                  className={({ isActive }) =>
                    `flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium uppercase tracking-wider transition-all ${
                      isActive
                        ? item.highlight
                          ? 'bg-[#ff5500]/15 text-[#ff5500] border border-[#ff5500]/40 font-bold'
                          : 'bg-white text-[#141416] border border-[#dedad2] shadow-sm'
                        : item.highlight
                        ? 'text-[#ff5500] hover:bg-[#ff5500]/10 border border-transparent'
                        : 'text-[#787570] hover:text-[#141416] hover:bg-white/60 border border-transparent'
                    }`
                  }
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span className="hidden md:inline">{item.name}</span>
                </NavLink>
              );
            })}
          </nav>

          {/* Engine Status Indicator */}
          <div className="hidden lg:flex items-center gap-3 border-l border-[#dedad2] pl-4">
            <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-white border border-[#dedad2]">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
              <span className="text-[11px] font-medium text-[#141416] uppercase">Defense Grid Active</span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
