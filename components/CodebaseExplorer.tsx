'use client';

import React, { useState } from 'react';
import { SERVER_FILES, ServerFile } from '@/lib/server-files';
import { FileText, Copy, Check, Download, Code, Layers, FileCode } from 'lucide-react';

interface CodebaseExplorerProps {
  onDownloadZip: () => void;
  isDownloadingZip: boolean;
}

export function CodebaseExplorer({ onDownloadZip, isDownloadingZip }: CodebaseExplorerProps) {
  const [activeFile, setActiveFile] = useState<ServerFile>(SERVER_FILES[0]);
  const [copied, setCopied] = useState(false);

  const copyContent = () => {
    navigator.clipboard.writeText(activeFile.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const lineCount = activeFile.content.split('\n').length;

  return (
    <div className="space-y-4">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 rounded-xl border border-neutral-800 bg-neutral-900/60 p-4">
        <div>
          <h3 className="text-base font-semibold text-white">Full GitHub-Ready Repository Files</h3>
          <p className="text-xs text-neutral-400 mt-0.5">
            Every file required to run the HexStrike FastMCP server on Render or local Docker.
          </p>
        </div>

        <button
          onClick={onDownloadZip}
          disabled={isDownloadingZip}
          className="flex items-center gap-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-4 py-2 text-xs font-semibold text-neutral-950 transition-colors disabled:opacity-50"
        >
          <Download className="h-4 w-4" />
          <span>{isDownloadingZip ? 'Preparing ZIP Archive...' : 'Download All Files (.zip)'}</span>
        </button>
      </div>

      {/* Main File Browser layout */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-4 rounded-xl border border-neutral-800 bg-neutral-900/40 p-4">
        {/* Left File Tree */}
        <div className="md:col-span-4 space-y-1">
          <span className="text-[11px] font-mono uppercase text-neutral-400 font-semibold px-2 mb-2 block">
            Repository Structure ({SERVER_FILES.length} files)
          </span>

          <div className="space-y-1">
            {SERVER_FILES.map((file) => {
              const isActive = activeFile.name === file.name;
              return (
                <button
                  key={file.name}
                  onClick={() => setActiveFile(file)}
                  className={`w-full flex items-center justify-between px-3 py-2 text-xs font-mono rounded-lg transition-colors text-left ${
                    isActive
                      ? 'bg-emerald-950/60 border border-emerald-500/40 text-emerald-300'
                      : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/40 border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-2 truncate">
                    <FileCode className={`h-4 w-4 shrink-0 ${isActive ? 'text-emerald-400' : 'text-neutral-500'}`} />
                    <span className="truncate">{file.name}</span>
                  </div>
                  <span className="text-[10px] text-neutral-500 font-sans ml-2 uppercase shrink-0">
                    {file.language}
                  </span>
                </button>
              );
            })}
          </div>

          <div className="p-3 mt-4 rounded-lg bg-neutral-950 border border-neutral-800/80 text-xs text-neutral-400 space-y-1.5">
            <p className="font-semibold text-neutral-300">File Description:</p>
            <p className="text-[11px] leading-relaxed text-neutral-400">{activeFile.description}</p>
          </div>
        </div>

        {/* Right Code Display */}
        <div className="md:col-span-8 flex flex-col rounded-lg border border-neutral-800 bg-neutral-950 overflow-hidden">
          {/* File bar */}
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-neutral-800 bg-neutral-900/70">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-semibold text-emerald-400">{activeFile.path}</span>
              <span className="text-neutral-500 text-[11px]">({lineCount} lines)</span>
            </div>

            <button
              onClick={copyContent}
              className="flex items-center gap-1.5 rounded bg-neutral-800 hover:bg-neutral-700 px-2.5 py-1 text-xs text-neutral-200 transition-colors"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>

          {/* Code Viewer */}
          <div className="relative flex-1 overflow-auto max-h-[560px] p-4 font-mono text-xs text-emerald-300/90 leading-relaxed">
            <pre className="whitespace-pre">{activeFile.content}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}
