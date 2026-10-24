'use client';

import React from 'react';
import { Shield, Server, Terminal, Github, ExternalLink, Zap } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onDownloadZip: () => void;
  isDownloadingZip: boolean;
}

export function Navbar({ activeTab, setActiveTab, onDownloadZip, isDownloadingZip }: NavbarProps) {
  const navItems = [
    { id: 'maps-scraper', label: 'Google Maps Scraper' },
    { id: 'render', label: 'Render 24/7 Setup' },
    { id: 'claude', label: 'Claude MCP Config' },
    { id: 'playground', label: 'Live Tool Tester' },
    { id: 'codebase', label: 'Files & GitHub Repo' },
    { id: 'ping', label: 'Ping / Health' },
  ];

  return (
    <header className="sticky top-0 z-50 border-b border-neutral-800 bg-neutral-950/90 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3 sm:px-6">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold tracking-tight text-white text-base">HexStrike AI</span>
              <span className="text-xs font-mono text-emerald-400 border border-emerald-500/20 px-1.5 py-0.5 rounded bg-emerald-950/30">
                FastMCP
              </span>
            </div>
            <p className="text-[11px] text-neutral-400 font-mono">Reverse Engineering & Cyber MCP Server</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="hidden lg:flex items-center gap-1 rounded-lg border border-neutral-800 bg-neutral-900/60 p-1">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                activeTab === item.id
                  ? 'bg-neutral-800 text-white shadow-sm'
                  : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/40'
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>

        {/* Actions */}
        <div className="flex items-center gap-2">
          <a
            href="https://github.com/0x4m4/hexstrike-ai"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 text-xs font-mono text-neutral-400 hover:text-neutral-200 border border-neutral-800 hover:border-neutral-700 px-2.5 py-1.5 rounded-md transition-colors bg-neutral-900/50"
            title="View upstream 0x4m4/hexstrike-ai GitHub repo"
          >
            <Github className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">0x4m4/hexstrike-ai</span>
            <ExternalLink className="h-3 w-3 opacity-60" />
          </a>

          <button
            onClick={onDownloadZip}
            disabled={isDownloadingZip}
            className="flex items-center gap-1.5 rounded-md bg-emerald-500 hover:bg-emerald-400 px-3 py-1.5 text-xs font-semibold text-neutral-950 transition-colors disabled:opacity-50"
          >
            <Zap className="h-3.5 w-3.5 fill-current" />
            <span>{isDownloadingZip ? 'Bundling...' : 'Download Code (ZIP)'}</span>
          </button>
        </div>
      </div>

      {/* Mobile nav bar */}
      <div className="flex lg:hidden overflow-x-auto border-t border-neutral-800/80 px-4 py-2 gap-1 scrollbar-none">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={`whitespace-nowrap px-3 py-1 text-xs font-medium rounded-md transition-colors ${
              activeTab === item.id
                ? 'bg-neutral-800 text-white'
                : 'text-neutral-400 hover:text-neutral-200'
            }`}
          >
            {item.label}
          </button>
        ))}
      </div>
    </header>
  );
}
