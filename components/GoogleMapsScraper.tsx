'use client';

import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  MapPin,
  Search,
  Download,
  Copy,
  Check,
  Globe,
  Mail,
  Phone,
  ExternalLink,
  RefreshCw,
  Terminal,
  Filter,
  Share2,
  Linkedin,
  Facebook,
  Instagram,
  Twitter,
  ChevronDown,
  ChevronUp,
  Sparkles,
  Layers,
  Building2,
  Star,
  Users,
} from 'lucide-react';
import { BusinessLead } from '@/app/api/gmaps-scraper/route';

const SAMPLE_PRESETS = [
  { query: 'Dental Clinics', location: 'Austin, TX' },
  { query: 'Coffee Roasters', location: 'Seattle, WA' },
  { query: 'Plumbing & HVAC', location: 'Chicago, IL' },
  { query: 'Boutique Hotels', location: 'Miami, FL' },
  { query: 'AI & SaaS Startups', location: 'San Francisco, CA' },
  { query: 'Roofing Contractors', location: 'Denver, CO' },
];

const PIPELINE_STATUSES: BusinessLead['status'][] = [
  'New',
  'Contacted',
  'Qualified',
  'Disqualified',
  'Won',
];

export function GoogleMapsScraper() {
  const [query, setQuery] = useState('Dental Clinics');
  const [location, setLocation] = useState('Austin, TX');
  const [limit, setLimit] = useState(15);
  const [enrichContacts, setEnrichContacts] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [leads, setLeads] = useState<BusinessLead[]>([]);
  const [selectedLead, setSelectedLead] = useState<BusinessLead | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // Filter state
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [onlyWithEmail, setOnlyWithEmail] = useState(false);
  const [onlyWithPhone, setOnlyWithPhone] = useState(false);
  const [sortBy, setSortBy] = useState<'rating' | 'reviews' | 'name'>('rating');

  // UI state
  const [showLogs, setShowLogs] = useState(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [csvCopied, setCsvCopied] = useState(false);

  const handleScrape = useCallback(async (e?: boolean | React.FormEvent) => {
    if (typeof e === 'object' && e?.preventDefault) {
      e.preventDefault();
    }
    setIsLoading(true);
    setLogs((prev) => [
      `[INIT] Querying Google Maps directory for "${query}" in "${location}" (Depth: ${limit})...`,
    ]);

    try {
      const res = await fetch('/api/gmaps-scraper', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query,
          location,
          limit,
          enrichContacts,
        }),
      });

      const data = await res.json();
      if (data.leads && Array.isArray(data.leads)) {
        setLeads(data.leads);
        setSelectedIds(new Set());
        if (data.crawlLogs) {
          setLogs(data.crawlLogs);
        }
      } else {
        setLogs((prev) => [...prev, `[ERROR] Failed to fetch leads: ${data.error || 'Unknown'}`]);
      }
    } catch (err: any) {
      setLogs((prev) => [...prev, `[ERROR] Network error: ${err.message}`]);
    } finally {
      setIsLoading(false);
    }
  }, [query, location, limit, enrichContacts]);

  // Initial load
  useEffect(() => {
    handleScrape(false);
  }, [handleScrape]);

  const handleStatusChange = (id: string, newStatus: BusinessLead['status']) => {
    setLeads((prev) =>
      prev.map((lead) => (lead.id === id ? { ...lead, status: newStatus } : lead))
    );
    if (selectedLead && selectedLead.id === id) {
      setSelectedLead((prev) => (prev ? { ...prev, status: newStatus } : null));
    }
  };

  const handleBulkStatusChange = (newStatus: BusinessLead['status']) => {
    if (selectedIds.size === 0) return;
    setLeads((prev) =>
      prev.map((lead) => (selectedIds.has(lead.id) ? { ...lead, status: newStatus } : lead))
    );
  };

  const toggleSelectAll = () => {
    if (selectedIds.size === filteredLeads.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filteredLeads.map((l) => l.id)));
    }
  };

  const toggleSelectOne = (id: string) => {
    const next = new Set(selectedIds);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
    }
    setSelectedIds(next);
  };

  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Filtered and sorted leads
  const filteredLeads = useMemo(() => {
    return leads
      .filter((lead) => {
        if (statusFilter !== 'ALL' && lead.status !== statusFilter) return false;
        if (onlyWithEmail && (!lead.emails || lead.emails.length === 0)) return false;
        if (onlyWithPhone && !lead.phone) return false;
        if (searchTerm.trim()) {
          const s = searchTerm.toLowerCase();
          const matchName = lead.name.toLowerCase().includes(s);
          const matchCat = lead.category.toLowerCase().includes(s);
          const matchAddr = lead.address.toLowerCase().includes(s);
          const matchEmail = lead.emails.some((e) => e.toLowerCase().includes(s));
          if (!matchName && !matchCat && !matchAddr && !matchEmail) return false;
        }
        return true;
      })
      .sort((a, b) => {
        if (sortBy === 'rating') return b.rating - a.rating;
        if (sortBy === 'reviews') return b.reviewsCount - a.reviewsCount;
        return a.name.localeCompare(b.name);
      });
  }, [leads, statusFilter, onlyWithEmail, onlyWithPhone, searchTerm, sortBy]);

  // Export CSV
  const handleExportCSV = () => {
    const targetLeads = selectedIds.size > 0 ? leads.filter((l) => selectedIds.has(l.id)) : filteredLeads;
    if (targetLeads.length === 0) return;

    const headers = [
      'ID',
      'Name',
      'Category',
      'Address',
      'City',
      'Phone',
      'Website',
      'Emails',
      'LinkedIn',
      'Facebook',
      'Instagram',
      'Twitter',
      'Rating',
      'Reviews_Count',
      'Pipeline_Status',
      'Google_Maps_URL',
      'Latitude',
      'Longitude',
    ];

    const escapeCsv = (val: any) => {
      if (val === null || val === undefined) return '""';
      const str = String(val).replace(/"/g, '""');
      return `"${str}"`;
    };

    const rows = targetLeads.map((l) => [
      escapeCsv(l.id),
      escapeCsv(l.name),
      escapeCsv(l.category),
      escapeCsv(l.address),
      escapeCsv(l.city),
      escapeCsv(l.phone),
      escapeCsv(l.website),
      escapeCsv(l.emails.join('; ')),
      escapeCsv(l.socialLinks.linkedin || ''),
      escapeCsv(l.socialLinks.facebook || ''),
      escapeCsv(l.socialLinks.instagram || ''),
      escapeCsv(l.socialLinks.twitter || ''),
      escapeCsv(l.rating),
      escapeCsv(l.reviewsCount),
      escapeCsv(l.status),
      escapeCsv(l.placeUrl),
      escapeCsv(l.latitude),
      escapeCsv(l.longitude),
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `gmaps_leads_${query.replace(/\s+/g, '_')}_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Export JSON
  const handleExportJSON = () => {
    const targetLeads = selectedIds.size > 0 ? leads.filter((l) => selectedIds.has(l.id)) : filteredLeads;
    const jsonStr = JSON.stringify(targetLeads, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `gmaps_leads_${query.replace(/\s+/g, '_')}_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleCopyCSV = () => {
    const targetLeads = selectedIds.size > 0 ? leads.filter((l) => selectedIds.has(l.id)) : filteredLeads;
    const headers = ['Name', 'Phone', 'Website', 'Emails', 'Rating', 'Address', 'Status'];
    const rows = targetLeads.map((l) => [
      l.name,
      l.phone,
      l.website,
      l.emails.join('; '),
      l.rating,
      l.address,
      l.status,
    ]);
    const csvContent = [headers.join(','), ...rows.map((r) => r.map((c) => `"${c}"`).join(','))].join('\n');
    navigator.clipboard.writeText(csvContent);
    setCsvCopied(true);
    setTimeout(() => setCsvCopied(false), 2000);
  };

  // Pipeline stats
  const stats = useMemo(() => {
    const total = leads.length;
    const withEmail = leads.filter((l) => l.emails.length > 0).length;
    const withPhone = leads.filter((l) => Boolean(l.phone)).length;
    const statusCounts = PIPELINE_STATUSES.reduce((acc, st) => {
      acc[st] = leads.filter((l) => l.status === st).length;
      return acc;
    }, {} as Record<string, number>);
    const avgRating = total > 0 ? (leads.reduce((a, b) => a + b.rating, 0) / total).toFixed(1) : '0.0';

    return { total, withEmail, withPhone, statusCounts, avgRating };
  }, [leads]);

  return (
    <div className="space-y-6">
      {/* Header & Sub-hero */}
      <div className="rounded-xl border border-neutral-800 bg-neutral-900/40 p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <MapPin className="h-4 w-4" />
              </div>
              <h2 className="text-xl font-bold tracking-tight text-white">Google Maps Lead Scraper Kit</h2>
              <span className="text-xs font-mono text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded bg-emerald-950/40">
                Keyless & FastMCP Ready
              </span>
            </div>
            <p className="text-sm text-neutral-400">
              Extract targeted B2B business leads, crawl company websites for verified emails, social media handles, phone numbers, and manage your sales pipeline.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleExportCSV}
              disabled={leads.length === 0}
              className="flex items-center gap-1.5 rounded-lg border border-neutral-700 hover:border-neutral-600 bg-neutral-900 px-3 py-2 text-xs font-medium text-white transition-colors disabled:opacity-50"
            >
              <Download className="h-3.5 w-3.5 text-emerald-400" />
              <span>Export CSV</span>
            </button>

            <button
              onClick={handleExportJSON}
              disabled={leads.length === 0}
              className="flex items-center gap-1.5 rounded-lg border border-neutral-700 hover:border-neutral-600 bg-neutral-900 px-3 py-2 text-xs font-medium text-white transition-colors disabled:opacity-50"
            >
              <Download className="h-3.5 w-3.5 text-emerald-400" />
              <span>Export JSON</span>
            </button>

            <button
              onClick={handleCopyCSV}
              disabled={leads.length === 0}
              className="flex items-center gap-1.5 rounded-lg border border-neutral-700 hover:border-neutral-600 bg-neutral-900 px-3 py-2 text-xs font-medium text-white transition-colors disabled:opacity-50"
            >
              {csvCopied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5 text-neutral-400" />}
              <span>{csvCopied ? 'Copied!' : 'Copy to Clipboard'}</span>
            </button>
          </div>
        </div>

        {/* Quick Presets */}
        <div className="mt-4 pt-4 border-t border-neutral-800/80 flex flex-wrap items-center gap-2">
          <span className="text-xs font-mono text-neutral-400">Quick Industry Presets:</span>
          {SAMPLE_PRESETS.map((p, idx) => (
            <button
              key={idx}
              onClick={() => {
                setQuery(p.query);
                setLocation(p.location);
              }}
              className="rounded-md border border-neutral-800 bg-neutral-950/80 hover:bg-neutral-800/60 px-2.5 py-1 text-xs text-neutral-300 hover:text-white transition-colors"
            >
              {p.query} in {p.location}
            </button>
          ))}
        </div>
      </div>

      {/* Scraper Configuration Form */}
      <form
        onSubmit={handleScrape}
        className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-5 space-y-4"
      >
        <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
          <div className="md:col-span-4 space-y-1.5">
            <label className="text-xs font-semibold text-neutral-300">Target Industry or Keyword</label>
            <div className="relative">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-neutral-500" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="e.g. Dental Clinics, Coffee Roasters, Law Firms..."
                className="w-full rounded-lg border border-neutral-700 bg-neutral-950 pl-9 pr-3 py-2 text-xs text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
              />
            </div>
          </div>

          <div className="md:col-span-4 space-y-1.5">
            <label className="text-xs font-semibold text-neutral-300">City & Geolocation</label>
            <div className="relative">
              <MapPin className="absolute left-3 top-2.5 h-4 w-4 text-neutral-500" />
              <input
                type="text"
                value={location}
                onChange={(e) => setLocation(e.target.value)}
                placeholder="e.g. Austin, TX or London, UK..."
                className="w-full rounded-lg border border-neutral-700 bg-neutral-950 pl-9 pr-3 py-2 text-xs text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
              />
            </div>
          </div>

          <div className="md:col-span-2 space-y-1.5">
            <label className="text-xs font-semibold text-neutral-300">Max Leads</label>
            <select
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
              className="w-full rounded-lg border border-neutral-700 bg-neutral-950 px-3 py-2 text-xs text-white focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            >
              <option value={10}>10 Leads</option>
              <option value={15}>15 Leads</option>
              <option value={20}>20 Leads</option>
              <option value={30}>30 Leads</option>
            </select>
          </div>

          <div className="md:col-span-2 flex items-end">
            <button
              type="submit"
              disabled={isLoading}
              className="w-full flex items-center justify-center gap-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 px-4 py-2 text-xs font-semibold text-neutral-950 transition-colors disabled:opacity-50 shadow-md shadow-emerald-500/10"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
              <span>{isLoading ? 'Scraping...' : 'Start Extraction'}</span>
            </button>
          </div>
        </div>

        {/* Enrichment toggles */}
        <div className="flex flex-wrap items-center justify-between gap-4 pt-3 border-t border-neutral-800/80 text-xs">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={enrichContacts}
              onChange={(e) => setEnrichContacts(e.target.checked)}
              className="rounded border-neutral-700 bg-neutral-950 text-emerald-500 focus:ring-emerald-500 h-4 w-4"
            />
            <span className="text-neutral-300 font-medium">
              Crawl business websites automatically for contact emails and social links
            </span>
          </label>

          <button
            type="button"
            onClick={() => setShowLogs(!showLogs)}
            className="flex items-center gap-1.5 text-neutral-400 hover:text-white font-mono text-xs"
          >
            <Terminal className="h-3.5 w-3.5" />
            <span>Terminal Crawl Logs</span>
            {showLogs ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          </button>
        </div>
      </form>

      {/* Real-time Crawl Log Terminal */}
      {showLogs && (
        <div className="rounded-xl border border-neutral-800 bg-neutral-950 overflow-hidden font-mono text-xs">
          <div className="flex items-center justify-between border-b border-neutral-800/80 px-4 py-2 bg-neutral-900/60">
            <div className="flex items-center gap-2">
              <span className="flex h-2 w-2 rounded-full bg-emerald-400"></span>
              <span className="text-neutral-400 text-[11px]">SCRAPER_WORKER_ENGINE: Active Crawl Stream</span>
            </div>
            <span className="text-neutral-500 text-[10px] tabular-nums font-mono">{logs.length} events logged</span>
          </div>
          <div className="h-28 overflow-y-auto p-3 space-y-1 scrollbar-thin">
            {logs.map((log, index) => (
              <div
                key={index}
                className={`text-[11px] leading-relaxed ${
                  log.includes('[ERROR]')
                    ? 'text-rose-400'
                    : log.includes('[SUCCESS]')
                    ? 'text-emerald-400 font-semibold'
                    : log.includes('[ENRICHER]')
                    ? 'text-cyan-400'
                    : 'text-neutral-400'
                }`}
              >
                {log}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Metrics Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-xl border border-neutral-800 bg-neutral-900/40 p-4">
          <span className="text-xs font-mono text-neutral-400">Total Leads</span>
          <p className="mt-1 text-2xl font-bold tracking-tight text-white tabular-nums font-mono">
            {stats.total}
          </p>
          <p className="text-[11px] text-neutral-500 mt-0.5">Discovered on Google Maps</p>
        </div>

        <div className="rounded-xl border border-neutral-800 bg-neutral-900/40 p-4">
          <span className="text-xs font-mono text-neutral-400">Verified Emails</span>
          <p className="mt-1 text-2xl font-bold tracking-tight text-emerald-400 tabular-nums font-mono">
            {stats.withEmail}
          </p>
          <p className="text-[11px] text-neutral-500 mt-0.5">
            {stats.total > 0 ? `${Math.round((stats.withEmail / stats.total) * 100)}% contact rate` : '0%'}
          </p>
        </div>

        <div className="rounded-xl border border-neutral-800 bg-neutral-900/40 p-4">
          <span className="text-xs font-mono text-neutral-400">Phone Numbers</span>
          <p className="mt-1 text-2xl font-bold tracking-tight text-white tabular-nums font-mono">
            {stats.withPhone}
          </p>
          <p className="text-[11px] text-neutral-500 mt-0.5">Direct line verified</p>
        </div>

        <div className="rounded-xl border border-neutral-800 bg-neutral-900/40 p-4">
          <span className="text-xs font-mono text-neutral-400">Avg Google Rating</span>
          <p className="mt-1 text-2xl font-bold tracking-tight text-amber-400 tabular-nums font-mono flex items-center gap-1">
            <span>{stats.avgRating}</span>
            <Star className="h-4 w-4 fill-amber-400 text-amber-400 inline" />
          </p>
          <p className="text-[11px] text-neutral-500 mt-0.5">High reputation threshold</p>
        </div>
      </div>

      {/* Filter and Pipeline Bar */}
      <div className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Status Tabs */}
          <div className="flex flex-wrap items-center gap-1 text-xs">
            <span className="text-neutral-400 font-mono mr-1">Status:</span>
            {['ALL', ...PIPELINE_STATUSES].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 rounded-md font-mono text-xs transition-colors ${
                  statusFilter === st
                    ? 'bg-emerald-500 text-neutral-950 font-bold'
                    : 'bg-neutral-950 text-neutral-400 hover:text-white border border-neutral-800'
                }`}
              >
                {st} {st !== 'ALL' && `(${stats.statusCounts[st] || 0})`}
              </button>
            ))}
          </div>

          {/* Quick search input */}
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-neutral-500" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search extracted leads..."
                className="rounded-md border border-neutral-700 bg-neutral-950 pl-8 pr-3 py-1.5 text-xs text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none"
              />
            </div>

            <select
              value={sortBy}
              onChange={(e: any) => setSortBy(e.target.value)}
              className="rounded-md border border-neutral-700 bg-neutral-950 px-2 py-1.5 text-xs text-white focus:border-emerald-500 focus:outline-none"
            >
              <option value="rating">Sort: Highest Rating</option>
              <option value="reviews">Sort: Most Reviews</option>
              <option value="name">Sort: Business Name</option>
            </select>
          </div>
        </div>

        {/* Checkbox filters & Bulk actions */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-neutral-800/60 text-xs">
          <div className="flex items-center gap-4">
            <label className="flex items-center gap-1.5 cursor-pointer text-neutral-300">
              <input
                type="checkbox"
                checked={onlyWithEmail}
                onChange={(e) => setOnlyWithEmail(e.target.checked)}
                className="rounded border-neutral-700 bg-neutral-950 text-emerald-500"
              />
              <span>With Email only</span>
            </label>

            <label className="flex items-center gap-1.5 cursor-pointer text-neutral-300">
              <input
                type="checkbox"
                checked={onlyWithPhone}
                onChange={(e) => setOnlyWithPhone(e.target.checked)}
                className="rounded border-neutral-700 bg-neutral-950 text-emerald-500"
              />
              <span>With Phone only</span>
            </label>
          </div>

          {selectedIds.size > 0 && (
            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="text-emerald-400 font-semibold">{selectedIds.size} selected</span>
              <span className="text-neutral-500">· Set Pipeline:</span>
              {PIPELINE_STATUSES.map((st) => (
                <button
                  key={st}
                  onClick={() => handleBulkStatusChange(st)}
                  className="rounded border border-neutral-700 bg-neutral-950 hover:bg-neutral-800 px-2 py-0.5 text-[11px] text-neutral-300 hover:text-white"
                >
                  {st}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Main Leads Data Grid */}
      <div className="rounded-xl border border-neutral-800 bg-neutral-900/40 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-neutral-800 bg-neutral-900/90 text-[11px] font-mono uppercase text-neutral-400">
              <tr>
                <th className="p-3 w-8">
                  <input
                    type="checkbox"
                    checked={selectedIds.size === filteredLeads.length && filteredLeads.length > 0}
                    onChange={toggleSelectAll}
                    className="rounded border-neutral-700 bg-neutral-950 text-emerald-500"
                  />
                </th>
                <th className="p-3">Business Entity</th>
                <th className="p-3">Contact Information</th>
                <th className="p-3">Social Profiles</th>
                <th className="p-3">Rating & Reviews</th>
                <th className="p-3">Pipeline Status</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-800/80">
              {filteredLeads.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-12 text-center text-neutral-500">
                    <Building2 className="h-8 w-8 mx-auto mb-2 opacity-30 text-neutral-400" />
                    <p className="text-sm font-medium text-neutral-400">No leads match your filter criteria.</p>
                    <p className="text-xs text-neutral-600 mt-1">
                      Try adjusting the search query or reset status filters.
                    </p>
                  </td>
                </tr>
              ) : (
                filteredLeads.map((lead) => (
                  <tr
                    key={lead.id}
                    className="hover:bg-neutral-900/80 transition-colors group"
                  >
                    {/* Checkbox */}
                    <td className="p-3">
                      <input
                        type="checkbox"
                        checked={selectedIds.has(lead.id)}
                        onChange={() => toggleSelectOne(lead.id)}
                        className="rounded border-neutral-700 bg-neutral-950 text-emerald-500"
                      />
                    </td>

                    {/* Business Entity (Zero-pill discipline: unboxed text with · separators) */}
                    <td className="p-3 max-w-xs">
                      <div className="space-y-0.5">
                        <div className="font-semibold text-white flex items-center gap-1.5">
                          <span>{lead.name}</span>
                          {lead.verified && (
                            <span className="text-[10px] font-mono text-emerald-400 font-normal">
                              ✓ Verified
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-neutral-400">
                          <span>{lead.category}</span>
                          <span className="mx-1.5 text-neutral-600">·</span>
                          <span className="truncate">{lead.city}</span>
                        </div>
                        <div className="text-[11px] text-neutral-500 font-mono truncate" title={lead.address}>
                          {lead.address}
                        </div>
                      </div>
                    </td>

                    {/* Contact Information */}
                    <td className="p-3">
                      <div className="space-y-1">
                        {lead.phone && (
                          <div className="flex items-center gap-1.5 font-mono text-[11px] text-neutral-300">
                            <Phone className="h-3 w-3 text-neutral-500" />
                            <span className="tabular-nums">{lead.phone}</span>
                            <button
                              onClick={() => handleCopyText(lead.phone, `phone_${lead.id}`)}
                              className="opacity-0 group-hover:opacity-100 transition-opacity hover:text-white"
                              title="Copy phone"
                            >
                              {copiedId === `phone_${lead.id}` ? (
                                <Check className="h-2.5 w-2.5 text-emerald-400" />
                              ) : (
                                <Copy className="h-2.5 w-2.5 text-neutral-500" />
                              )}
                            </button>
                          </div>
                        )}

                        {lead.emails && lead.emails.length > 0 ? (
                          <div className="flex items-center gap-1.5 font-mono text-[11px] text-emerald-300">
                            <Mail className="h-3 w-3 text-emerald-400" />
                            <span className="truncate max-w-[180px]">{lead.emails[0]}</span>
                            <button
                              onClick={() => handleCopyText(lead.emails[0], `email_${lead.id}`)}
                              className="hover:text-white"
                              title="Copy email"
                            >
                              {copiedId === `email_${lead.id}` ? (
                                <Check className="h-2.5 w-2.5 text-emerald-400" />
                              ) : (
                                <Copy className="h-2.5 w-2.5 text-neutral-500" />
                              )}
                            </button>
                          </div>
                        ) : (
                          <span className="text-[11px] text-neutral-600 italic">No email found</span>
                        )}

                        {lead.website && (
                          <div className="flex items-center gap-1.5 text-[11px] text-cyan-400">
                            <Globe className="h-3 w-3 text-neutral-500" />
                            <a
                              href={lead.website}
                              target="_blank"
                              rel="noreferrer"
                              className="hover:underline truncate max-w-[180px]"
                            >
                              {lead.website.replace('https://', '').replace('http://', '')}
                            </a>
                          </div>
                        )}
                      </div>
                    </td>

                    {/* Social Profiles */}
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        {lead.socialLinks.linkedin && (
                          <a
                            href={lead.socialLinks.linkedin}
                            target="_blank"
                            rel="noreferrer"
                            className="p-1 rounded bg-neutral-950 border border-neutral-800 text-neutral-400 hover:text-sky-400 hover:border-sky-500/30 transition-colors"
                            title="LinkedIn Company Page"
                          >
                            <Linkedin className="h-3 w-3" />
                          </a>
                        )}
                        {lead.socialLinks.facebook && (
                          <a
                            href={lead.socialLinks.facebook}
                            target="_blank"
                            rel="noreferrer"
                            className="p-1 rounded bg-neutral-950 border border-neutral-800 text-neutral-400 hover:text-blue-400 hover:border-blue-500/30 transition-colors"
                            title="Facebook Page"
                          >
                            <Facebook className="h-3 w-3" />
                          </a>
                        )}
                        {lead.socialLinks.instagram && (
                          <a
                            href={lead.socialLinks.instagram}
                            target="_blank"
                            rel="noreferrer"
                            className="p-1 rounded bg-neutral-950 border border-neutral-800 text-neutral-400 hover:text-pink-400 hover:border-pink-500/30 transition-colors"
                            title="Instagram Profile"
                          >
                            <Instagram className="h-3 w-3" />
                          </a>
                        )}
                        {lead.socialLinks.twitter && (
                          <a
                            href={lead.socialLinks.twitter}
                            target="_blank"
                            rel="noreferrer"
                            className="p-1 rounded bg-neutral-950 border border-neutral-800 text-neutral-400 hover:text-white hover:border-neutral-700 transition-colors"
                            title="X / Twitter"
                          >
                            <Twitter className="h-3 w-3" />
                          </a>
                        )}
                        {!lead.socialLinks.linkedin &&
                          !lead.socialLinks.facebook &&
                          !lead.socialLinks.instagram &&
                          !lead.socialLinks.twitter && (
                            <span className="text-[11px] text-neutral-600 font-mono">-</span>
                          )}
                      </div>
                    </td>

                    {/* Rating & Reviews */}
                    <td className="p-3 font-mono">
                      <div className="flex items-center gap-1.5">
                        <span className="font-semibold text-amber-400 tabular-nums">{lead.rating}</span>
                        <div className="flex">
                          {[...Array(5)].map((_, i) => (
                            <Star
                              key={i}
                              className={`h-2.5 w-2.5 ${
                                i < Math.floor(lead.rating)
                                  ? 'fill-amber-400 text-amber-400'
                                  : 'text-neutral-700'
                              }`}
                            />
                          ))}
                        </div>
                      </div>
                      <div className="text-[10px] text-neutral-500 tabular-nums mt-0.5">
                        {lead.reviewsCount} verified reviews
                      </div>
                    </td>

                    {/* Pipeline Status Selector */}
                    <td className="p-3">
                      <select
                        value={lead.status}
                        onChange={(e: any) => handleStatusChange(lead.id, e.target.value)}
                        className={`rounded px-2 py-1 text-xs font-mono font-medium border ${
                          lead.status === 'Won'
                            ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-400'
                            : lead.status === 'Qualified'
                            ? 'bg-blue-950/60 border-blue-500/40 text-blue-400'
                            : lead.status === 'Contacted'
                            ? 'bg-amber-950/60 border-amber-500/40 text-amber-400'
                            : lead.status === 'Disqualified'
                            ? 'bg-rose-950/60 border-rose-500/40 text-rose-400'
                            : 'bg-neutral-950 border-neutral-800 text-neutral-300'
                        }`}
                      >
                        {PIPELINE_STATUSES.map((st) => (
                          <option key={st} value={st}>
                            {st}
                          </option>
                        ))}
                      </select>
                    </td>

                    {/* Actions */}
                    <td className="p-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => setSelectedLead(lead)}
                          className="rounded p-1 text-neutral-400 hover:text-white hover:bg-neutral-800 transition-colors"
                          title="View lead dossier"
                        >
                          <Layers className="h-3.5 w-3.5" />
                        </button>
                        <a
                          href={lead.placeUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="rounded p-1 text-neutral-400 hover:text-emerald-400 hover:bg-neutral-800 transition-colors"
                          title="Open on Google Maps"
                        >
                          <ExternalLink className="h-3.5 w-3.5" />
                        </a>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Lead Detail Modal */}
      {selectedLead && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-2xl rounded-2xl border border-neutral-800 bg-neutral-950 p-6 shadow-2xl space-y-6">
            <div className="flex items-start justify-between border-b border-neutral-800 pb-4">
              <div>
                <h3 className="text-lg font-bold text-white">{selectedLead.name}</h3>
                <p className="text-xs text-neutral-400 mt-0.5">
                  {selectedLead.category} · {selectedLead.city} · {selectedLead.rating} ★ ({selectedLead.reviewsCount} reviews)
                </p>
              </div>
              <button
                onClick={() => setSelectedLead(null)}
                className="rounded-lg p-1 text-neutral-400 hover:text-white hover:bg-neutral-900 transition-colors"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
              <div className="space-y-1">
                <span className="text-neutral-500 font-mono">Full Address</span>
                <p className="font-medium text-white">{selectedLead.address}</p>
              </div>

              <div className="space-y-1">
                <span className="text-neutral-500 font-mono">Phone Number</span>
                <p className="font-mono text-emerald-400">{selectedLead.phone || 'N/A'}</p>
              </div>

              <div className="space-y-1">
                <span className="text-neutral-500 font-mono">Website</span>
                <p className="text-cyan-400 truncate">
                  <a href={selectedLead.website} target="_blank" rel="noreferrer" className="hover:underline">
                    {selectedLead.website}
                  </a>
                </p>
              </div>

              <div className="space-y-1">
                <span className="text-neutral-500 font-mono">Pipeline Status</span>
                <div>
                  <select
                    value={selectedLead.status}
                    onChange={(e: any) => handleStatusChange(selectedLead.id, e.target.value)}
                    className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-white"
                  >
                    {PIPELINE_STATUSES.map((st) => (
                      <option key={st} value={st}>
                        {st}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="space-y-1 sm:col-span-2">
                <span className="text-neutral-500 font-mono">Crawled Email Addresses</span>
                {selectedLead.emails.length > 0 ? (
                  <div className="flex flex-wrap gap-2 pt-1">
                    {selectedLead.emails.map((em, i) => (
                      <span
                        key={i}
                        className="rounded bg-neutral-900 border border-neutral-800 px-2.5 py-1 text-xs font-mono text-emerald-300 flex items-center gap-1.5"
                      >
                        <Mail className="h-3 w-3 text-emerald-400" />
                        <span>{em}</span>
                        <button
                          onClick={() => handleCopyText(em, `modal_email_${i}`)}
                          className="hover:text-white"
                        >
                          {copiedId === `modal_email_${i}` ? (
                            <Check className="h-3 w-3 text-emerald-400" />
                          ) : (
                            <Copy className="h-3 w-3 text-neutral-500" />
                          )}
                        </button>
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-neutral-500 italic">No public email found during web crawl.</p>
                )}
              </div>

              <div className="space-y-1 sm:col-span-2">
                <span className="text-neutral-500 font-mono">Opening Hours</span>
                <p className="text-neutral-300">{selectedLead.openingHours}</p>
              </div>

              <div className="space-y-1 sm:col-span-2">
                <span className="text-neutral-500 font-mono">Geolocation Coordinates</span>
                <p className="font-mono text-neutral-400">
                  Latitude: {selectedLead.latitude} · Longitude: {selectedLead.longitude}
                </p>
              </div>
            </div>

            <div className="flex items-center justify-between border-t border-neutral-800 pt-4">
              <a
                href={selectedLead.placeUrl}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400 hover:text-emerald-300"
              >
                <span>View Google Maps Listing</span>
                <ExternalLink className="h-3.5 w-3.5" />
              </a>

              <button
                onClick={() => setSelectedLead(null)}
                className="rounded-lg bg-neutral-800 hover:bg-neutral-700 px-4 py-2 text-xs font-semibold text-white transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
