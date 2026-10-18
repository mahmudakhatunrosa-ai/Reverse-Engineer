'use client';

import React, { useState } from 'react';
import { Server, Terminal, Copy, Check, Clock, Shield, AlertTriangle, ExternalLink, ArrowRight, Zap } from 'lucide-react';

export function RenderSetupGuide() {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const steps = [
    {
      num: '01',
      title: 'Push MCP Server to your GitHub Repository',
      desc: 'Create a new repository on GitHub (e.g. hexstrike-fastmcp) and push the server files.',
      cmd: `mkdir hexstrike-fastmcp
cd hexstrike-fastmcp
# Copy all generated files (server.py, requirements.txt, Dockerfile, etc.)
git init
git add .
git commit -m "Initial HexStrike FastMCP server"
git remote add origin https://github.com/YOUR_USERNAME/hexstrike-fastmcp.git
git branch -M main
git push -u origin main`,
      cmdKey: 'git_cmd',
    },
    {
      num: '02',
      title: 'Create a New Web Service on Render',
      desc: 'Connect your GitHub repository to Render for automatic build & deployment.',
      details: [
        'Open https://dashboard.render.com and sign in.',
        'Click the blue "New +" button in the top right, then select "Web Service".',
        'Choose "Build and deploy from a Git repository" and click Next.',
        'Select or search for your GitHub repository: hexstrike-fastmcp.',
      ],
    },
    {
      num: '03',
      title: 'Configure Service Settings',
      desc: 'Enter the exact Python + Uvicorn build & start commands so FastMCP boots properly.',
      config: [
        { label: 'Name', val: 'hexstrike-mcp (or your custom name)' },
        { label: 'Region', val: 'Oregon (US West) or Frankfurt (EU) - pick closest to you' },
        { label: 'Branch', val: 'main' },
        { label: 'Runtime', val: 'Python 3 (or Docker if using Dockerfile)' },
        {
          label: 'Build Command',
          val: 'pip install --upgrade pip && pip install -r requirements.txt',
          copyable: true,
          key: 'build_cmd',
        },
        {
          label: 'Start Command',
          val: 'uvicorn server:app --host 0.0.0.0 --port $PORT',
          copyable: true,
          key: 'start_cmd',
        },
        { label: 'Instance Type', val: 'Free ($0/mo) or Starter ($7/mo for guaranteed zero sleep)' },
      ],
    },
    {
      num: '04',
      title: 'Set Health Check & Environment Variables',
      desc: 'Click "Advanced" to add the health check path and config variables.',
      envVars: [
        { key: 'PYTHON_VERSION', val: '3.11.9', desc: 'Ensures Python 3.11 with FastMCP compatibility' },
        { key: 'LOG_LEVEL', val: 'info', desc: 'FastMCP logging verbosity' },
        { key: 'HEXSTRIKE_BACKEND_URL', val: 'http://localhost:8888', desc: 'Upstream HexStrike engine proxy (optional)' },
        { key: 'MCP_AUTH_TOKEN', val: '(leave empty or set a secret bearer token)', desc: 'Optional client authentication' },
      ],
      healthCheck: {
        path: '/health',
        desc: 'Render will poll this endpoint to verify container health and perform zero-downtime deploys.',
      },
    },
    {
      num: '05',
      title: 'Keeping It Running 24/7 Anytime (Free-Tier Sleep Fix)',
      desc: 'Render Free instances sleep after 15 min of inactivity. Keep your MCP server 100% awake with these options:',
      keepAliveOptions: [
        {
          title: 'Option A: Free Uptime Ping (100% Free 24/7)',
          text: 'Use a free ping service like UptimeRobot (uptimerobot.com) or Cron-job.org to ping https://your-app.onrender.com/health every 10 minutes. Your Render server will never go to sleep!',
          tag: 'Recommended Free',
        },
        {
          title: 'Option B: Background Keepalive Script',
          text: 'Run the included `python render_keepalive.py https://your-app.onrender.com` locally or on a VPS/GitHub Action to ping the health endpoint.',
          tag: 'Custom Script',
        },
        {
          title: 'Option C: Render Starter Plan ($7/mo)',
          text: 'Upgrade to Starter instance with continuous 24/7 CPU/RAM, instant response times, and 0 cold starts.',
          tag: 'Production',
        },
      ],
    },
  ];

  return (
    <div className="space-y-8">
      {/* Overview Banner */}
      <div className="rounded-xl border border-emerald-500/30 bg-gradient-to-r from-emerald-950/40 via-neutral-900 to-neutral-950 p-6">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400 uppercase tracking-wider">
                <Server className="h-3.5 w-3.5" /> Render 24/7 FastMCP Architecture
              </span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">Deploying HexStrike AI MCP Server to Render</h2>
            <p className="text-sm text-neutral-400 mt-1 max-w-2xl">
              Render hosts your Python FastMCP server as a background Web Service with public HTTPS and Server-Sent Events (SSE). 
              Claude Desktop or Claude Web can query it from anywhere.
            </p>
          </div>
          <a
            href="https://dashboard.render.com"
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-4 py-2 text-sm font-semibold text-neutral-950 transition-colors"
          >
            <span>Open Render Dashboard</span>
            <ExternalLink className="h-4 w-4" />
          </a>
        </div>
      </div>

      {/* Step by Step Cards */}
      <div className="space-y-6">
        {steps.map((step) => (
          <div
            key={step.num}
            className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-6 transition-all hover:border-neutral-700"
          >
            <div className="flex items-start gap-4">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-neutral-800 border border-neutral-700 text-emerald-400 font-mono font-bold text-sm">
                {step.num}
              </div>
              <div className="flex-1 space-y-3">
                <div>
                  <h3 className="text-base font-semibold text-white">{step.title}</h3>
                  <p className="text-sm text-neutral-400 mt-0.5">{step.desc}</p>
                </div>

                {/* Git command block */}
                {step.cmd && (
                  <div className="relative rounded-lg bg-neutral-950 border border-neutral-800 p-4 font-mono text-xs text-neutral-200">
                    <button
                      onClick={() => copyText(step.cmd, step.cmdKey || '')}
                      className="absolute top-3 right-3 flex items-center gap-1 rounded bg-neutral-800 hover:bg-neutral-700 px-2 py-1 text-[11px] text-neutral-300 transition-colors"
                    >
                      {copiedKey === step.cmdKey ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                      <span>{copiedKey === step.cmdKey ? 'Copied' : 'Copy'}</span>
                    </button>
                    <pre className="overflow-x-auto pr-16">{step.cmd}</pre>
                  </div>
                )}

                {/* Details list */}
                {step.details && (
                  <ul className="space-y-1.5 text-xs text-neutral-300 list-disc list-inside">
                    {step.details.map((d, i) => (
                      <li key={i}>{d}</li>
                    ))}
                  </ul>
                )}

                {/* Config table */}
                {step.config && (
                  <div className="overflow-hidden rounded-lg border border-neutral-800 bg-neutral-950/80">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-neutral-900/90 text-neutral-400 font-mono">
                        <tr>
                          <th className="p-3 font-medium">Setting Field</th>
                          <th className="p-3 font-medium">Value to Enter on Render</th>
                          <th className="p-3 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-neutral-800/60 font-mono">
                        {step.config.map((c, i) => (
                          <tr key={i} className="hover:bg-neutral-900/30">
                            <td className="p-3 font-medium text-neutral-300">{c.label}</td>
                            <td className="p-3 text-emerald-400 font-mono break-all">{c.val}</td>
                            <td className="p-3 text-right">
                              {c.copyable && c.key ? (
                                <button
                                  onClick={() => copyText(c.val, c.key || '')}
                                  className="inline-flex items-center gap-1 rounded bg-neutral-800 hover:bg-neutral-700 px-2 py-1 text-[11px] text-neutral-300 transition-colors"
                                >
                                  {copiedKey === c.key ? (
                                    <Check className="h-3 w-3 text-emerald-400" />
                                  ) : (
                                    <Copy className="h-3 w-3" />
                                  )}
                                  <span>{copiedKey === c.key ? 'Copied' : 'Copy'}</span>
                                </button>
                              ) : (
                                <span className="text-neutral-500 text-[11px]">—</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* Env vars & Health check */}
                {step.envVars && (
                  <div className="space-y-3">
                    <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-3">
                      <div className="flex items-center justify-between text-xs text-neutral-300 font-mono pb-2 border-b border-neutral-800 mb-2">
                        <span className="font-semibold text-emerald-400">Health Check Path:</span>
                        <span className="bg-emerald-950/50 text-emerald-400 px-2 py-0.5 rounded border border-emerald-500/20">
                          {step.healthCheck?.path}
                        </span>
                      </div>
                      <p className="text-xs text-neutral-400">{step.healthCheck?.desc}</p>
                    </div>

                    <div className="space-y-2">
                      <p className="text-xs font-semibold text-neutral-300">Environment Variables to Add:</p>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        {step.envVars.map((ev, i) => (
                          <div key={i} className="p-2.5 rounded-lg bg-neutral-950 border border-neutral-800 text-xs">
                            <div className="flex items-center justify-between">
                              <span className="font-mono text-emerald-400 font-semibold">{ev.key}</span>
                              <span className="font-mono text-neutral-300 bg-neutral-900 px-1.5 py-0.5 rounded text-[11px]">
                                {ev.val}
                              </span>
                            </div>
                            <p className="text-[11px] text-neutral-400 mt-1">{ev.desc}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {/* Keep Alive Options */}
                {step.keepAliveOptions && (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
                    {step.keepAliveOptions.map((opt, i) => (
                      <div key={i} className="rounded-lg border border-neutral-800 bg-neutral-950 p-4 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold text-white">{opt.title}</span>
                        </div>
                        <p className="text-xs text-neutral-400 leading-relaxed">{opt.text}</p>
                        <div className="pt-2">
                          <span className="text-[10px] font-mono text-emerald-400 border border-emerald-500/20 bg-emerald-950/30 px-2 py-0.5 rounded">
                            {opt.tag}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
