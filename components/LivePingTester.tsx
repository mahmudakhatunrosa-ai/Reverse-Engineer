'use client';

import React, { useState } from 'react';
import { Activity, Globe, CheckCircle2, AlertCircle, RefreshCw, Clock } from 'lucide-react';

export function LivePingTester() {
  const [url, setUrl] = useState('https://hexstrike-mcp.onrender.com');
  const [isPinging, setIsPinging] = useState(false);
  const [pingResult, setPingResult] = useState<any>(null);

  const testEndpoint = async () => {
    setIsPinging(true);
    setPingResult(null);

    const clean = url.trim().replace(/\/+$/, '');
    const startTime = performance.now();

    try {
      // Test the endpoint via direct fetch
      const resp = await fetch(`${clean}/health`, {
        method: 'GET',
        headers: { Accept: 'application/json' },
      });
      const endTime = performance.now();
      const latency = Math.round(endTime - startTime);

      let data: any = null;
      try {
        data = await resp.json();
      } catch {
        data = await resp.text();
      }

      setPingResult({
        success: resp.ok,
        status: resp.status,
        statusText: resp.statusText,
        latencyMs: latency,
        data,
        targetUrl: `${clean}/health`,
      });
    } catch (err: any) {
      const endTime = performance.now();
      const latency = Math.round(endTime - startTime);
      setPingResult({
        success: false,
        error: err.message || 'Network request failed (possibly offline or spinning up on Render free tier)',
        latencyMs: latency,
        targetUrl: `${clean}/health`,
      });
    } finally {
      setIsPinging(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-6 space-y-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Activity className="h-4 w-4 text-emerald-400" />
            <h3 className="text-base font-semibold text-white">Live Health & Latency Ping Tester</h3>
          </div>
          <p className="text-xs text-neutral-400">
            Verify if your Render FastMCP deployment is awake, responding to health probes, and ready for Claude.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://your-service-name.onrender.com"
            className="flex-1 rounded-lg border border-neutral-700 bg-neutral-950 px-4 py-2.5 font-mono text-sm text-emerald-300 placeholder-neutral-600 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
          />
          <button
            onClick={testEndpoint}
            disabled={isPinging}
            className="flex items-center justify-center gap-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-5 py-2.5 text-xs font-semibold text-neutral-950 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${isPinging ? 'animate-spin' : ''}`} />
            <span>{isPinging ? 'Pinging Endpoint...' : 'Send Probe (Ping)'}</span>
          </button>
        </div>

        <p className="text-[11px] text-neutral-400">
          Probes <code className="text-emerald-400 font-mono">{url.trim().replace(/\/+$/, '')}/health</code>. Note: If your Render free instance was asleep, the initial wake-up may take 20–40 seconds.
        </p>
      </div>

      {/* Results Box */}
      {pingResult && (
        <div
          className={`rounded-xl border p-5 space-y-3 ${
            pingResult.success
              ? 'border-emerald-500/30 bg-emerald-950/20'
              : 'border-amber-500/30 bg-amber-950/20'
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {pingResult.success ? (
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
              ) : (
                <AlertCircle className="h-5 w-5 text-amber-400" />
              )}
              <span className="text-sm font-semibold text-white">
                {pingResult.success ? 'Server Online & Healthy' : 'Probe Incomplete / Cold Start'}
              </span>
            </div>

            <div className="flex items-center gap-2 font-mono text-xs">
              <Clock className="h-3.5 w-3.5 text-neutral-400" />
              <span className="text-neutral-300">{pingResult.latencyMs} ms</span>
            </div>
          </div>

          <div className="rounded-lg bg-neutral-950 p-3 font-mono text-xs text-neutral-300 space-y-1">
            <p>
              <span className="text-neutral-500">Target:</span> {pingResult.targetUrl}
            </p>
            {pingResult.status && (
              <p>
                <span className="text-neutral-500">HTTP Status:</span>{' '}
                <span className={pingResult.success ? 'text-emerald-400' : 'text-amber-400'}>
                  {pingResult.status} {pingResult.statusText}
                </span>
              </p>
            )}
            {pingResult.error && (
              <p className="text-rose-400">
                <span className="text-neutral-500">Error:</span> {pingResult.error}
              </p>
            )}
            {pingResult.data && (
              <pre className="text-emerald-300 mt-2 text-[11px]">
                {typeof pingResult.data === 'string'
                  ? pingResult.data
                  : JSON.stringify(pingResult.data, null, 2)}
              </pre>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
