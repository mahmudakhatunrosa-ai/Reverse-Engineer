'use client';

import React, { useState } from 'react';
import { Navbar } from '@/components/Navbar';
import { RenderSetupGuide } from '@/components/RenderSetupGuide';
import { ClaudeConfigurator } from '@/components/ClaudeConfigurator';
import { ToolPlayground } from '@/components/ToolPlayground';
import { CodebaseExplorer } from '@/components/CodebaseExplorer';
import { LivePingTester } from '@/components/LivePingTester';
import { SERVER_FILES } from '@/lib/server-files';
import JSZip from 'jszip';
import {
  Shield,
  Server,
  Terminal,
  Cpu,
  Zap,
  ArrowRight,
  Download,
  CheckCircle,
  Activity,
  Layers,
  Code,
  Globe,
} from 'lucide-react';

export default function Home() {
  const [activeTab, setActiveTab] = useState('render');
  const [isDownloadingZip, setIsDownloadingZip] = useState(false);

  const handleDownloadZip = async () => {
    setIsDownloadingZip(true);
    try {
      const zip = new JSZip();
      SERVER_FILES.forEach((file) => {
        zip.file(file.name, file.content);
      });
      const blob = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'hexstrike-fastmcp-render.zip';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to create zip:', err);
    } finally {
      setIsDownloadingZip(false);
    }
  };

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100 selection:bg-emerald-500 selection:text-neutral-950">
      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onDownloadZip={handleDownloadZip}
        isDownloadingZip={isDownloadingZip}
      />

      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 sm:py-12 space-y-12">
        {/* Hero Section */}
        <section className="relative overflow-hidden rounded-2xl border border-neutral-800 bg-gradient-to-b from-neutral-900 via-neutral-950 to-neutral-950 p-6 sm:p-10">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(16,185,129,0.15),rgba(255,255,255,0))]" />
          
          <div className="relative z-10 max-w-3xl space-y-4">
            <div className="inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-950/40 px-3 py-1 text-xs font-mono text-emerald-400">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span>FastMCP Protocol · 24/7 Render Web Service Ready</span>
            </div>

            <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white leading-tight">
              HexStrike AI <span className="text-emerald-400 font-mono">FastMCP Server</span>
            </h1>

            <p className="text-base sm:text-lg text-neutral-300 leading-relaxed max-w-2xl">
              Turn <span className="font-semibold text-white">0x4m4/hexstrike-ai</span> into a remote 24/7 Model Context Protocol (MCP) server. 
              Empower Claude Desktop, Claude Web, Cursor, and Windsurf to autonomously disassemble binaries, detect packers, decompile pseudocode, and audit security mitigations.
            </p>

            {/* CTAs */}
            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                onClick={() => setActiveTab('render')}
                className="flex items-center gap-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-5 py-2.5 text-sm font-semibold text-neutral-950 transition-all shadow-lg shadow-emerald-500/20"
              >
                <span>Render 24/7 Setup Guide</span>
                <ArrowRight className="h-4 w-4" />
              </button>

              <button
                onClick={() => setActiveTab('claude')}
                className="flex items-center gap-2 rounded-lg border border-neutral-700 hover:border-neutral-600 bg-neutral-900 px-5 py-2.5 text-sm font-semibold text-white transition-colors"
              >
                <Terminal className="h-4 w-4 text-emerald-400" />
                <span>Claude MCP Config</span>
              </button>

              <button
                onClick={handleDownloadZip}
                disabled={isDownloadingZip}
                className="flex items-center gap-2 rounded-lg border border-emerald-500/30 hover:bg-emerald-950/30 px-5 py-2.5 text-sm font-semibold text-emerald-400 transition-colors disabled:opacity-50"
              >
                <Download className="h-4 w-4" />
                <span>{isDownloadingZip ? 'Bundling ZIP...' : 'Download Code ZIP'}</span>
              </button>
            </div>
          </div>

          {/* Key Stats Bar */}
          <div className="relative z-10 mt-8 grid grid-cols-2 sm:grid-cols-4 gap-3 pt-6 border-t border-neutral-800/80 font-mono text-xs">
            <div className="space-y-0.5">
              <span className="text-neutral-500">Framework</span>
              <p className="font-semibold text-white">Python 3.11 + FastMCP</p>
            </div>
            <div className="space-y-0.5">
              <span className="text-neutral-500">Transport</span>
              <p className="font-semibold text-emerald-400">HTTP + SSE (/sse)</p>
            </div>
            <div className="space-y-0.5">
              <span className="text-neutral-500">Hosting</span>
              <p className="font-semibold text-white">Render (24/7 Web Service)</p>
            </div>
            <div className="space-y-0.5">
              <span className="text-neutral-500">Target AI Clients</span>
              <p className="font-semibold text-emerald-400">Claude, Cursor, Windsurf</p>
            </div>
          </div>
        </section>

        {/* Dynamic Tab Contents */}
        <section className="space-y-6">
          {activeTab === 'render' && <RenderSetupGuide />}
          {activeTab === 'claude' && <ClaudeConfigurator />}
          {activeTab === 'playground' && <ToolPlayground />}
          {activeTab === 'codebase' && (
            <CodebaseExplorer onDownloadZip={handleDownloadZip} isDownloadingZip={isDownloadingZip} />
          )}
          {activeTab === 'ping' && <LivePingTester />}
        </section>

        {/* Footer */}
        <footer className="border-t border-neutral-800/80 pt-6 pb-12 flex flex-col sm:flex-row items-center justify-between text-xs text-neutral-500 gap-4">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-emerald-500" />
            <span>HexStrike AI FastMCP Server · Compatible with 0x4m4/hexstrike-ai</span>
          </div>
          <div className="flex items-center gap-4">
            <button
              onClick={() => setActiveTab('render')}
              className="hover:text-neutral-300 transition-colors"
            >
              Render Guide
            </button>
            <button
              onClick={() => setActiveTab('claude')}
              className="hover:text-neutral-300 transition-colors"
            >
              Claude Config
            </button>
            <button
              onClick={() => setActiveTab('codebase')}
              className="hover:text-neutral-300 transition-colors"
            >
              View Files
            </button>
            <a
              href="https://github.com/0x4m4/hexstrike-ai"
              target="_blank"
              rel="noreferrer"
              className="hover:text-neutral-300 transition-colors"
            >
              Upstream Repo
            </a>
          </div>
        </footer>
      </main>
    </div>
  );
}
