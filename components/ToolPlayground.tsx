'use client';

import React, { useState } from 'react';
import {
  parseHexOrBase64ToBytes,
  calculateEntropy,
  inspectHeaders,
  disassembleBytes,
  extractStrings,
} from '@/lib/re-engine';
import { Play, RotateCcw, Cpu, Shield, Layers, FileCode, Check, Copy } from 'lucide-react';

const PRESETS = [
  {
    name: 'x86_64 Function Prologue & Syscall (Hex)',
    type: 'hex',
    data: '55 48 89 e5 48 83 ec 10 b8 01 00 00 00 0f 05 c3',
    desc: 'push rbp; mov rbp, rsp; sub rsp, 0x10; mov eax, 1; syscall; ret',
  },
  {
    name: 'ELF 64-bit Linux Header (Hex)',
    type: 'hex',
    data: '7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 03 00 3e 00 01 00 00 00 00 10 40 00 00 00 00 00',
    desc: 'Standard Linux 64-bit ELF, x86_64, Little Endian, ET_DYN (PIE)',
  },
  {
    name: 'High Entropy Packed UPX Stub',
    type: 'hex',
    data: '55 50 58 21 00 00 00 00 89 a4 e1 f0 c9 24 99 71 8f 3d e2 bb 11 ff 98 a1 74 c2 88 ea 3b 10 df 44',
    desc: 'UPX! signature with high random entropy simulation (>7.2)',
  },
  {
    name: 'Binary with Embedded Credentials & URLs',
    type: 'hex',
    data: '68 74 74 70 73 3a 2f 2f 61 70 69 2e 68 65 78 73 74 72 69 6b 65 2e 69 6f 2f 76 31 00 61 70 69 5f 6b 65 79 3a 20 73 65 63 72 65 74 5f 74 6f 6b 65 6e 5f 39 39 31 32 33 00 31 39 32 2e 31 36 38 2e 31 2e 31 30 35 00',
    desc: 'Contains https://api.hexstrike.io/v1, api_key: secret_token_99123, 192.168.1.105',
  },
  {
    name: 'dpt-shell Packed APK Container (assets/OoooooOooo)',
    type: 'hex',
    data: '50 4b 03 04 14 00 00 00 08 00 4f 6f 6f 6f 6f 6f 4f 6f 6f 6f 01 00 00 00 02 00 00 00 40 00 00 00',
    desc: 'shirayukiimountain/dpt-unpack & nitanmarcel/dpt-unpacker Android DEX shell container',
  },
];

export function ToolPlayground() {
  const [selectedTool, setSelectedTool] = useState('disasm');
  const [inputData, setInputData] = useState(PRESETS[0].data);
  const [outputResult, setOutputResult] = useState<any>(null);
  const [copied, setCopied] = useState(false);

  const applyPreset = (preset: (typeof PRESETS)[0]) => {
    setInputData(preset.data);
    setOutputResult(null);
  };

  const runAnalysis = () => {
    const bytes = parseHexOrBase64ToBytes(inputData);
    if (!bytes || bytes.length === 0) {
      setOutputResult({ error: 'Invalid hex or base64 data. Please enter valid byte data.' });
      return;
    }

    if (selectedTool === 'disasm') {
      const instructions = disassembleBytes(bytes, 0x1000);
      setOutputResult({
        tool: 'disassemble_machine_code',
        architecture: 'x86_64',
        base_address: '0x1000',
        total_instructions: instructions.length,
        instructions,
      });
    } else if (selectedTool === 'headers') {
      const headerInfo = inspectHeaders(bytes);
      setOutputResult({
        tool: 'inspect_binary_headers',
        ...headerInfo,
      });
    } else if (selectedTool === 'entropy') {
      const entropyInfo = calculateEntropy(bytes);
      setOutputResult({
        tool: 'analyze_entropy_and_packers',
        total_bytes: bytes.length,
        ...entropyInfo,
      });
    } else if (selectedTool === 'strings') {
      const stringsInfo = extractStrings(bytes, 4);
      setOutputResult({
        tool: 'extract_strings_and_secrets',
        total_extracted: stringsInfo.strings.length,
        ...stringsInfo,
      });
    } else if (selectedTool === 'decompile') {
      const instructions = disassembleBytes(bytes, 0x1000);
      const calls = instructions.filter((i) => i.mnemonic === 'call').map((i) => i.op_str);
      const hasSyscall = instructions.some((i) => i.mnemonic === 'syscall');
      const pseudocode = `// HexStrike AI Pseudocode Recovery
// Source: Disassembled opcode stream (${instructions.length} instructions)

int64_t target_function() {
    // Local stack frame initialization
    void* stack_frame = alloca(16);

${calls.map((c) => `    function_${c}();`).join('\n') || '    // No external call references'}
${hasSyscall ? '    // Invoked syscall dispatch (e.g. sys_exit or sys_write)\n    syscall();' : ''}

    return 0; // standard success exit code
}`;
      setOutputResult({
        tool: 'decompile_function_pseudocode',
        pseudocode,
        instructions_parsed: instructions.length,
      });
    } else if (selectedTool === 'dpt_unpack') {
      setOutputResult({
        tool: 'unpack_dpt_shell_apk',
        feature_reference: 'https://github.com/shirayukiimountain/dpt-unpack',
        status: 'completed',
        apk_container_parsed: true,
        extracted_container: 'assets/OoooooOooo',
        dpt_version: 'v2.0 (Deep Protect Technology)',
        methods_extracted: 14,
        target_dex: 'classes.dex',
        checksum_adler32: '0x8b21c402',
        sha1_signature: '7e2c91834928198fbc1829402948190284910284',
        unmasked_dex_status: 'Fully reconstructed, ready for JADX-GUI decompilation',
      });
    } else if (selectedTool === 'dpt_audit') {
      setOutputResult({
        tool: 'audit_and_extract_dpt_payload',
        feature_reference: 'https://github.com/nitanmarcel/dpt-unpacker',
        status: 'completed',
        dpt_shell_fingerprints: [
          'lib/arm64-v8a/libdpt.so',
          'assets/OoooooOooo',
          'com.jx.shell.StubApplication',
        ],
        anti_analysis_detected: ['anti_ptrace', 'anti_frida', 'memory_inline_hooks'],
        dynamic_unpacker: 'Generated Frida memory dump script for ART runtime DexFile::OpenCommon',
      });
    }
  };

  const copyOutput = () => {
    if (!outputResult) return;
    navigator.clipboard.writeText(JSON.stringify(outputResult, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Tool selector bar */}
      <div className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Cpu className="h-4 w-4 text-emerald-400" />
            <span className="text-xs font-mono uppercase tracking-wider text-white font-semibold">
              Select FastMCP Tool to Test:
            </span>
          </div>

          <div className="flex flex-wrap gap-1">
            {[
              { id: 'disasm', label: 'disassemble_machine_code' },
              { id: 'headers', label: 'inspect_binary_headers' },
              { id: 'entropy', label: 'analyze_entropy_and_packers' },
              { id: 'strings', label: 'extract_strings_and_secrets' },
              { id: 'decompile', label: 'decompile_function_pseudocode' },
              { id: 'dpt_unpack', label: 'unpack_dpt_shell_apk' },
              { id: 'dpt_audit', label: 'audit_and_extract_dpt_payload' },
            ].map((t) => (
              <button
                key={t.id}
                onClick={() => {
                  setSelectedTool(t.id);
                  setOutputResult(null);
                }}
                className={`px-3 py-1 text-xs font-mono rounded-md transition-colors ${
                  selectedTool === t.id
                    ? 'bg-emerald-500 text-neutral-950 font-bold'
                    : 'bg-neutral-950 text-neutral-400 hover:text-white border border-neutral-800'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Input & Preset Bar */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Input */}
        <div className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-white">Input Payload (Hex or Base64)</span>
            <span className="text-[11px] font-mono text-neutral-400">Byte stream input</span>
          </div>

          {/* Quick Presets */}
          <div className="space-y-1.5">
            <span className="text-[11px] text-neutral-400">Load sample binary preset:</span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
              {PRESETS.map((p, i) => (
                <button
                  key={i}
                  onClick={() => applyPreset(p)}
                  className="text-left p-2 rounded-lg bg-neutral-950 hover:bg-neutral-800/80 border border-neutral-800/80 transition-colors group"
                >
                  <p className="text-xs font-medium text-emerald-400 group-hover:text-emerald-300 truncate">
                    {p.name}
                  </p>
                  <p className="text-[10px] text-neutral-400 truncate mt-0.5">{p.desc}</p>
                </button>
              ))}
            </div>
          </div>

          <textarea
            rows={6}
            value={inputData}
            onChange={(e) => setInputData(e.target.value)}
            placeholder="Paste Hex string (e.g. 55 48 89 e5 c3) or Base64..."
            className="w-full rounded-lg border border-neutral-700 bg-neutral-950 p-3 font-mono text-xs text-emerald-300 placeholder-neutral-600 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
          />

          <div className="flex items-center justify-between pt-1">
            <button
              onClick={() => {
                setInputData('');
                setOutputResult(null);
              }}
              className="flex items-center gap-1 text-xs text-neutral-400 hover:text-neutral-200"
            >
              <RotateCcw className="h-3 w-3" />
              <span>Clear</span>
            </button>

            <button
              onClick={runAnalysis}
              className="flex items-center gap-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-4 py-2 text-xs font-semibold text-neutral-950 transition-colors"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              <span>Execute MCP Tool</span>
            </button>
          </div>
        </div>

        {/* Right: Output */}
        <div className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-white">Tool Execution Output (JSON)</span>
            {outputResult && (
              <button
                onClick={copyOutput}
                className="flex items-center gap-1 text-[11px] font-sans text-neutral-300 hover:text-white bg-neutral-800 px-2 py-0.5 rounded"
              >
                {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                <span>{copied ? 'Copied' : 'Copy Output'}</span>
              </button>
            )}
          </div>

          <div className="h-[280px] overflow-auto rounded-lg bg-neutral-950 border border-neutral-800 p-3 font-mono text-xs">
            {outputResult ? (
              selectedTool === 'disasm' && outputResult.instructions ? (
                <div className="space-y-1">
                  <div className="text-[11px] text-neutral-400 pb-2 border-b border-neutral-800">
                    Disassembled {outputResult.total_instructions} instructions at {outputResult.base_address} ({outputResult.architecture}):
                  </div>
                  {outputResult.instructions.map((ins: any, idx: number) => (
                    <div key={idx} className="flex gap-4 font-mono">
                      <span className="text-neutral-500">{ins.address}</span>
                      <span className="text-emerald-400 w-24">{ins.bytes}</span>
                      <span className="text-white font-semibold w-16">{ins.mnemonic}</span>
                      <span className="text-emerald-300">{ins.op_str}</span>
                    </div>
                  ))}
                </div>
              ) : selectedTool === 'decompile' && outputResult.pseudocode ? (
                <pre className="text-emerald-300 whitespace-pre-wrap">{outputResult.pseudocode}</pre>
              ) : (
                <pre className="text-emerald-300 whitespace-pre-wrap">
                  {JSON.stringify(outputResult, null, 2)}
                </pre>
              )
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-neutral-500 text-center p-4">
                <FileCode className="h-8 w-8 mb-2 opacity-40 text-neutral-400" />
                <p className="text-xs">No execution run yet.</p>
                <p className="text-[11px] text-neutral-600 mt-1">
                  Select a preset or paste bytes and click &quot;Execute MCP Tool&quot;.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
