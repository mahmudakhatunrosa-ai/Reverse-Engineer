'use client';

import React, { useState } from 'react';
import { Terminal, Copy, Check, ExternalLink, Sparkles, Cpu, Layers } from 'lucide-react';

export function ClaudeConfigurator() {
  const [renderUrl, setRenderUrl] = useState('https://hexstrike-mcp.onrender.com');
  const [clientType, setClientType] = useState<'claude-desktop' | 'cursor' | 'windsurf' | 'claude-cli'>('claude-desktop');
  const [copied, setCopied] = useState(false);

  // Clean trailing slashes
  const cleanUrl = renderUrl.trim().replace(/\/+$/, '');
  const sseEndpoint = `${cleanUrl}/sse`;

  const claudeDesktopConfig = {
    mcpServers: {
      'hexstrike-reverse-engineering': {
        command: 'npx',
        args: ['-y', 'mcp-remote', sseEndpoint],
      },
    },
  };

  const cursorConfig = {
    mcpServers: {
      'hexstrike-ai': {
        url: sseEndpoint,
        transport: 'sse',
      },
    },
  };

  const windsurfConfig = {
    mcpServers: {
      'hexstrike-ai': {
        serverUrl: sseEndpoint,
      },
    },
  };

  const claudeCliCommand = `claude mcp add hexstrike -- transport sse ${sseEndpoint}`;

  const currentSnippet =
    clientType === 'claude-desktop'
      ? JSON.stringify(claudeDesktopConfig, null, 2)
      : clientType === 'cursor'
      ? JSON.stringify(cursorConfig, null, 2)
      : clientType === 'windsurf'
      ? JSON.stringify(windsurfConfig, null, 2)
      : claudeCliCommand;

  const copyConfig = () => {
    navigator.clipboard.writeText(currentSnippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* URL Input Box */}
      <div className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-6 space-y-4">
        <div>
          <label className="text-xs font-mono uppercase tracking-wider text-emerald-400 font-semibold block mb-1">
            Step 1: Enter your Render Deployment URL
          </label>
          <p className="text-sm text-neutral-400">
            Paste the public URL given by Render after deploying your Web Service:
          </p>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <input
              type="text"
              value={renderUrl}
              onChange={(e) => setRenderUrl(e.target.value)}
              placeholder="https://your-service-name.onrender.com"
              className="w-full rounded-lg border border-neutral-700 bg-neutral-950 px-4 py-2.5 font-mono text-sm text-emerald-300 placeholder-neutral-600 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            />
          </div>
          <div className="flex items-center text-xs font-mono text-neutral-400 bg-neutral-950 border border-neutral-800 px-3 py-2 rounded-lg">
            <span>SSE Endpoint:</span>
            <span className="ml-2 text-emerald-400 font-semibold break-all">{sseEndpoint}</span>
          </div>
        </div>
      </div>

      {/* Client Selector & Snippet */}
      <div className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-base font-semibold text-white">Step 2: Connect to your AI Client</h3>
            <p className="text-xs text-neutral-400 mt-0.5">
              Select your AI client to generate the exact configuration block.
            </p>
          </div>

          {/* Toggle buttons */}
          <div className="flex flex-wrap gap-1 rounded-lg border border-neutral-800 bg-neutral-950 p-1">
            <button
              onClick={() => setClientType('claude-desktop')}
              className={`px-3 py-1 text-xs font-medium rounded ${
                clientType === 'claude-desktop'
                  ? 'bg-emerald-500 text-neutral-950 font-semibold'
                  : 'text-neutral-400 hover:text-white'
              }`}
            >
              Claude Desktop
            </button>
            <button
              onClick={() => setClientType('cursor')}
              className={`px-3 py-1 text-xs font-medium rounded ${
                clientType === 'cursor'
                  ? 'bg-emerald-500 text-neutral-950 font-semibold'
                  : 'text-neutral-400 hover:text-white'
              }`}
            >
              Cursor
            </button>
            <button
              onClick={() => setClientType('windsurf')}
              className={`px-3 py-1 text-xs font-medium rounded ${
                clientType === 'windsurf'
                  ? 'bg-emerald-500 text-neutral-950 font-semibold'
                  : 'text-neutral-400 hover:text-white'
              }`}
            >
              Windsurf
            </button>
            <button
              onClick={() => setClientType('claude-cli')}
              className={`px-3 py-1 text-xs font-medium rounded ${
                clientType === 'claude-cli'
                  ? 'bg-emerald-500 text-neutral-950 font-semibold'
                  : 'text-neutral-400 hover:text-white'
              }`}
            >
              Claude Code CLI
            </button>
          </div>
        </div>

        {/* Where to paste guide */}
        <div className="rounded-lg bg-neutral-950 border border-neutral-800 p-3 text-xs text-neutral-300">
          <span className="font-semibold text-emerald-400">File location to edit: </span>
          {clientType === 'claude-desktop' && (
            <span className="font-mono text-neutral-300">
              macOS: <code className="text-emerald-300">~/Library/Application Support/Claude/claude_desktop_config.json</code> | Windows: <code className="text-emerald-300">%APPDATA%\Claude\claude_desktop_config.json</code>
            </span>
          )}
          {clientType === 'cursor' && (
            <span className="font-mono text-neutral-300">
              <code className="text-emerald-300">~/.cursor/mcp.json</code> or Settings → Features → MCP
            </span>
          )}
          {clientType === 'windsurf' && (
            <span className="font-mono text-neutral-300">
              <code className="text-emerald-300">~/.codeium/windsurf/mcp_config.json</code>
            </span>
          )}
          {clientType === 'claude-cli' && (
            <span className="font-mono text-neutral-300">Run this command in terminal</span>
          )}
        </div>

        {/* Code Block with Copy */}
        <div className="relative rounded-lg bg-neutral-950 border border-neutral-800 p-4 font-mono text-xs text-emerald-300">
          <button
            onClick={copyConfig}
            className="absolute top-3 right-3 flex items-center gap-1 rounded bg-neutral-800 hover:bg-neutral-700 px-3 py-1.5 text-xs font-sans text-neutral-200 transition-colors"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            <span>{copied ? 'Copied to Clipboard' : 'Copy Configuration'}</span>
          </button>
          <pre className="overflow-x-auto pr-36">{currentSnippet}</pre>
        </div>

        {/* Pro-tip on mcp-remote */}
        {clientType === 'claude-desktop' && (
          <div className="rounded-lg border border-emerald-500/20 bg-emerald-950/20 p-3 text-xs text-neutral-300 leading-relaxed">
            <p className="font-semibold text-emerald-400 mb-1">How Claude Desktop connects to Remote Render:</p>
            Claude Desktop executes local tools over standard input/output (stdio). The command{' '}
            <code className="font-mono text-emerald-300 bg-neutral-900 px-1 py-0.5 rounded">npx -y mcp-remote {sseEndpoint}</code>{' '}
            acts as a zero-setup bridge that proxies Claude Desktop&apos;s stdio to your remote Render server over Server-Sent Events (SSE). No manual node install is required.
          </div>
        )}
      </div>

      {/* Prompts to test once connected */}
      <div className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-6 space-y-3">
        <h3 className="text-base font-semibold text-white">Step 3: Try These Prompts in Claude</h3>
        <p className="text-xs text-neutral-400">
          Once your MCP server is connected, restart Claude Desktop and paste any of these prompts into your chat:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
          {[
            {
              title: 'Disassemble x86_64 Machine Code',
              prompt:
                'Use HexStrike FastMCP to disassemble this hex opcode sequence: 4889e5b801000000c3 and explain the assembly function prologue and exit.',
            },
            {
              title: 'Detect Packed Trojan / UPX',
              prompt:
                'Analyze the entropy of this payload using HexStrike analyze_entropy_and_packers to see if it is compressed with UPX or Themida.',
            },
            {
              title: 'Binary Security Hardening Audit',
              prompt:
                'Inspect the ELF headers with audit_security_mitigations and report if ASLR, NX, and Stack Canaries are enforced.',
            },
            {
              title: 'Extract Secret API Keys and URLs',
              prompt:
                'Extract all strings, suspicious IPs, and potential hardcoded credentials from this binary using extract_strings_and_secrets.',
            },
          ].map((item, i) => (
            <div key={i} className="rounded-lg border border-neutral-800 bg-neutral-950 p-3.5 space-y-2">
              <span className="text-xs font-semibold text-emerald-400">{item.title}</span>
              <p className="text-xs font-mono text-neutral-300 italic bg-neutral-900/60 p-2 rounded border border-neutral-800/80">
                &ldquo;{item.prompt}&rdquo;
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
