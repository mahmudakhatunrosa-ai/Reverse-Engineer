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
  Send,
  MessageCircle,
  AlertCircle,
  CheckCircle2,
  X,
  Target,
} from 'lucide-react';
import { BusinessLead } from '@/app/api/gmaps-scraper/route';

const SAMPLE_PRESETS = [
  { query: 'Barber Shops', location: 'Austin, TX' },
  { query: 'Coffee Shops', location: 'Seattle, WA' },
  { query: 'Food Trucks', location: 'Miami, FL' },
  { query: 'Tattoo Studios', location: 'Brooklyn, NY' },
  { query: 'Plumbing & HVAC', location: 'Chicago, IL' },
  { query: 'Boutique Fitness', location: 'Denver, CO' },
];

const PIPELINE_STATUSES: BusinessLead['status'][] = [
  'New',
  'DMed on Instagram',
  'Contacted',
  'Qualified',
  'Disqualified',
  'Won',
];

export function GoogleMapsScraper() {
  const [query, setQuery] = useState('Barber Shops');
  const [location, setLocation] = useState('Austin, TX');
  const [limit, setLimit] = useState(15);
  const [enrichContacts, setEnrichContacts] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [leads, setLeads] = useState<BusinessLead[]>([]);
  const [selectedLead, setSelectedLead] = useState<BusinessLead | null>(null);
  const [outreachLead, setOutreachLead] = useState<BusinessLead | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // Filter state
  const [searchTerm, setSearchTerm] = useState('');
  const [websiteFilter, setWebsiteFilter] = useState<'ALL' | 'NO_WEBSITE' | 'HAS_WEBSITE'>('NO_WEBSITE');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [onlyWithPhone, setOnlyWithPhone] = useState(false);
  const [sortBy, setSortBy] = useState<'rating' | 'reviews' | 'name'>('rating');

  // UI feedback state
  const [showLogs, setShowLogs] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [csvCopied, setCsvCopied] = useState(false);

  const handleScrape = useCallback(async (e?: boolean | React.FormEvent) => {
    if (typeof e === 'object' && e?.preventDefault) {
      e.preventDefault();
    }
    setIsLoading(true);
    setLogs((prev) => [
      `[INIT] Querying Google Maps directory for "${query}" in "${location}" (Target: ${limit} leads)...`,
      `[ANALYZER] Detecting website status and identifying Instagram DM targets...`,
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
    if (outreachLead && outreachLead.id === id) {
      setOutreachLead((prev) => (prev ? { ...prev, status: newStatus } : null));
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
        // Website presence filter
        if (websiteFilter === 'NO_WEBSITE' && lead.hasWebsite) return false;
        if (websiteFilter === 'HAS_WEBSITE' && !lead.hasWebsite) return false;

        // Pipeline status filter
        if (statusFilter !== 'ALL' && lead.status !== statusFilter) return false;

        // Additional phone filter
        if (onlyWithPhone && !lead.phone) return false;

        // Search text term
        if (searchTerm.trim()) {
          const s = searchTerm.toLowerCase();
          const matchName = lead.name.toLowerCase().includes(s);
          const matchCat = lead.category.toLowerCase().includes(s);
          const matchAddr = lead.address.toLowerCase().includes(s);
          const matchIg = lead.instagramHandle?.toLowerCase().includes(s);
          if (!matchName && !matchCat && !matchAddr && !matchIg) return false;
        }
        return true;
      })
      .sort((a, b) => {
        if (sortBy === 'rating') return b.rating - a.rating;
        if (sortBy === 'reviews') return b.reviewsCount - a.reviewsCount;
        return a.name.localeCompare(b.name);
      });
  }, [leads, websiteFilter, statusFilter, onlyWithPhone, searchTerm, sortBy]);

  // Lead metrics
  const stats = useMemo(() => {
    const total = leads.length;
    const noWebsite = leads.filter((l) => !l.hasWebsite).length;
    const hasWebsite = leads.filter((l) => l.hasWebsite).length;
    const withPhone = leads.filter((l) => Boolean(l.phone)).length;
    const dmedCount = leads.filter((l) => l.status === 'DMed on Instagram').length;
    const statusCounts = PIPELINE_STATUSES.reduce((acc, st) => {
      acc[st] = leads.filter((l) => l.status === st).length;
      return acc;
    }, {} as Record<string, number>);
    const avgRating = total > 0 ? (leads.reduce((a, b) => a + b.rating, 0) / total).toFixed(1) : '0.0';

    return { total, noWebsite, hasWebsite, withPhone, dmedCount, statusCounts, avgRating };
  }, [leads]);

  // Export CSV
  const handleExportCSV = () => {
    const targetLeads = selectedIds.size > 0 ? leads.filter((l) => selectedIds.has(l.id)) : filteredLeads;
    if (targetLeads.length === 0) return;

    const headers = [
      'Business_Name',
      'Has_Website',
      'Website_URL',
      'Instagram_Handle',
      'Instagram_URL',
      'Phone',
      'Address',
      'City',
      'Category',
      'Rating',
      'Reviews_Count',
      'Pipeline_Status',
      'Cold_Instagram_Pitch',
      'Google_Maps_URL',
    ];

    const escapeCsv = (val: any) => {
      if (val === null || val === undefined) return '""';
      const str = String(val).replace(/"/g, '""');
      return `"${str}"`;
    };

    const rows = targetLeads.map((l) => {
      const igHandle = l.instagramHandle || `@${l.name.toLowerCase().replace(/[^a-z0-9]/g, '')}`;
      const igUrl = `https://www.instagram.com/${igHandle.replace('@', '')}/`;
      return [
        escapeCsv(l.name),
        escapeCsv(l.hasWebsite ? 'YES' : 'NO (DM Target)'),
        escapeCsv(l.website || 'NONE'),
        escapeCsv(igHandle),
        escapeCsv(igUrl),
        escapeCsv(l.phone),
        escapeCsv(l.address),
        escapeCsv(l.city),
        escapeCsv(l.category),
        escapeCsv(l.rating),
        escapeCsv(l.reviewsCount),
        escapeCsv(l.status),
        escapeCsv(l.instagramPitch || ''),
        escapeCsv(l.placeUrl),
      ];
    });

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `leads_${websiteFilter.toLowerCase()}_${query.replace(/\s+/g, '_')}_${Date.now()}.csv`);
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
    link.setAttribute('download', `leads_${query.replace(/\s+/g, '_')}_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleCopyClipboard = () => {
    const targetLeads = selectedIds.size > 0 ? leads.filter((l) => selectedIds.has(l.id)) : filteredLeads;
    const textList = targetLeads
      .map(
        (l) =>
          `• ${l.name} | ${l.hasWebsite ? `Website: ${l.website}` : 'NO WEBSITE (DM Target)'} | IG: ${l.instagramHandle || 'N/A'} | Phone: ${l.phone} | ${l.rating}★`
      )
      .join('\n');
    navigator.clipboard.writeText(textList);
    setCsvCopied(true);
    setTimeout(() => setCsvCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="rounded-xl border border-neutral-800 bg-neutral-900/40 p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-pink-500/10 border border-pink-500/30 text-pink-400">
                <Instagram className="h-4 w-4" />
              </div>
              <h2 className="text-xl font-bold tracking-tight text-white">Google Maps Lead Scraper & Instagram Outreach</h2>
              <span className="text-xs font-mono text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded bg-emerald-950/40">
                Live Directory Sourcing
              </span>
            </div>
            <p className="text-sm text-neutral-400">
              Find real local businesses, instantly distinguish who has a website vs. who doesn’t, grab their Instagram profiles, and send high-converting cold DM pitches to sell web design services.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleExportCSV}
              disabled={leads.length === 0}
              className="flex items-center gap-1.5 rounded-lg border border-neutral-700 hover:border-neutral-600 bg-neutral-900 px-3 py-2 text-xs font-medium text-white transition-colors disabled:opacity-50"
              title="Download filtered leads as CSV"
            >
              <Download className="h-3.5 w-3.5 text-emerald-400" />
              <span>Export CSV</span>
            </button>

            <button
              onClick={handleExportJSON}
              disabled={leads.length === 0}
              className="flex items-center gap-1.5 rounded-lg border border-neutral-700 hover:border-neutral-600 bg-neutral-900 px-3 py-2 text-xs font-medium text-white transition-colors disabled:opacity-50"
            >
              <Download className="h-3.5 w-3.5 text-cyan-400" />
              <span>Export JSON</span>
            </button>

            <button
              onClick={handleCopyClipboard}
              disabled={leads.length === 0}
              className="flex items-center gap-1.5 rounded-lg border border-neutral-700 hover:border-neutral-600 bg-neutral-900 px-3 py-2 text-xs font-medium text-white transition-colors disabled:opacity-50"
            >
              {csvCopied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5 text-neutral-400" />}
              <span>{csvCopied ? 'Copied!' : 'Copy Summary'}</span>
            </button>
          </div>
        </div>

        {/* Quick Presets */}
        <div className="mt-4 pt-4 border-t border-neutral-800/80 flex flex-wrap items-center gap-2">
          <span className="text-xs font-mono text-neutral-400">Target Presets:</span>
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

      {/* Scraper Search Form */}
      <form
        onSubmit={handleScrape}
        className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-5 space-y-4"
      >
        <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
          <div className="md:col-span-4 space-y-1.5">
            <label className="text-xs font-semibold text-neutral-300">Business Category / Industry</label>
            <div className="relative">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-neutral-500" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="e.g. Barber Shops, Coffee Roasters, Food Trucks, Dentists..."
                className="w-full rounded-lg border border-neutral-700 bg-neutral-950 pl-9 pr-3 py-2 text-xs text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
              />
            </div>
          </div>

          <div className="md:col-span-4 space-y-1.5">
            <label className="text-xs font-semibold text-neutral-300">City, State or Country</label>
            <div className="relative">
              <MapPin className="absolute left-3 top-2.5 h-4 w-4 text-neutral-500" />
              <input
                type="text"
                value={location}
                onChange={(e) => setLocation(e.target.value)}
                placeholder="e.g. Austin, TX or Miami, FL or London, UK..."
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
              <option value={8}>8 Leads</option>
              <option value={15}>15 Leads</option>
              <option value={20}>20 Leads</option>
              <option value={30}>30 Leads</option>
            </select>
          </div>

          <div className="md:col-span-2 flex items-end">
            <button
              type="submit"
              disabled={isLoading}
              className="w-full flex items-center justify-center gap-2 rounded-lg bg-pink-600 hover:bg-pink-500 px-4 py-2 text-xs font-semibold text-white transition-colors disabled:opacity-50 shadow-md shadow-pink-600/20"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
              <span>{isLoading ? 'Scraping Leads...' : 'Find Real Leads'}</span>
            </button>
          </div>
        </div>

        {/* Enrichment toggles & terminal log toggle */}
        <div className="flex flex-wrap items-center justify-between gap-4 pt-3 border-t border-neutral-800/80 text-xs">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={enrichContacts}
              onChange={(e) => setEnrichContacts(e.target.checked)}
              className="rounded border-neutral-700 bg-neutral-950 text-pink-500 focus:ring-pink-500 h-4 w-4"
            />
            <span className="text-neutral-300 font-medium">
              Crawl company websites live for public emails and social profiles
            </span>
          </label>

          <button
            type="button"
            onClick={() => setShowLogs(!showLogs)}
            className="flex items-center gap-1.5 text-neutral-400 hover:text-white font-mono text-xs"
          >
            <Terminal className="h-3.5 w-3.5" />
            <span>Terminal Scraper Logs</span>
            {showLogs ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          </button>
        </div>
      </form>

      {/* Scraper Log Terminal */}
      {showLogs && (
        <div className="rounded-xl border border-neutral-800 bg-neutral-950 overflow-hidden font-mono text-xs">
          <div className="flex items-center justify-between border-b border-neutral-800/80 px-4 py-2 bg-neutral-900/60">
            <div className="flex items-center gap-2">
              <span className="flex h-2 w-2 rounded-full bg-emerald-400"></span>
              <span className="text-neutral-400 text-[11px]">LEAD_INTELLIGENCE_STREAM: Real Directory Query</span>
            </div>
            <span className="text-neutral-500 text-[10px] tabular-nums font-mono">{logs.length} events logged</span>
          </div>
          <div className="h-32 overflow-y-auto p-3 space-y-1 scrollbar-thin">
            {logs.map((log, index) => (
              <div
                key={index}
                className={`text-[11px] leading-relaxed ${
                  log.includes('[ERROR]')
                    ? 'text-rose-400'
                    : log.includes('[METRICS]')
                    ? 'text-pink-400 font-semibold'
                    : log.includes('[SUCCESS]') || log.includes('[COMPLETED]')
                    ? 'text-emerald-400 font-semibold'
                    : log.includes('[SEARCH]')
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

      {/* Real Metrics Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-xl border border-neutral-800 bg-neutral-900/40 p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-neutral-400">Total Leads Found</span>
            <Building2 className="h-4 w-4 text-neutral-500" />
          </div>
          <p className="mt-2 text-2xl font-bold tracking-tight text-white tabular-nums font-mono">
            {stats.total}
          </p>
          <p className="text-[11px] text-neutral-500 mt-0.5">Real {query} in {location}</p>
        </div>

        {/* Highlighted NO WEBSITE Targets Card */}
        <div
          onClick={() => setWebsiteFilter('NO_WEBSITE')}
          className={`cursor-pointer rounded-xl border p-4 transition-all ${
            websiteFilter === 'NO_WEBSITE'
              ? 'border-pink-500/50 bg-pink-950/20 ring-1 ring-pink-500/30'
              : 'border-neutral-800 bg-neutral-900/40 hover:border-pink-500/30'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-pink-400 font-semibold flex items-center gap-1">
              <Target className="h-3.5 w-3.5" />
              <span>No Website (DM Targets)</span>
            </span>
            <span className="flex h-2 w-2 rounded-full bg-pink-400 animate-pulse"></span>
          </div>
          <p className="mt-2 text-2xl font-bold tracking-tight text-pink-300 tabular-nums font-mono">
            {stats.noWebsite}
          </p>
          <p className="text-[11px] text-pink-400/80 mt-0.5 font-medium">
            Prime web design prospects 🔥
          </p>
        </div>

        <div
          onClick={() => setWebsiteFilter('HAS_WEBSITE')}
          className={`cursor-pointer rounded-xl border p-4 transition-all ${
            websiteFilter === 'HAS_WEBSITE'
              ? 'border-cyan-500/50 bg-cyan-950/20 ring-1 ring-cyan-500/30'
              : 'border-neutral-800 bg-neutral-900/40 hover:border-cyan-500/30'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-neutral-400">Has Active Website</span>
            <Globe className="h-4 w-4 text-cyan-400" />
          </div>
          <p className="mt-2 text-2xl font-bold tracking-tight text-cyan-300 tabular-nums font-mono">
            {stats.hasWebsite}
          </p>
          <p className="text-[11px] text-neutral-500 mt-0.5">Redesign / speed pitch targets</p>
        </div>

        <div className="rounded-xl border border-neutral-800 bg-neutral-900/40 p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-neutral-400">DMed on Instagram</span>
            <Instagram className="h-4 w-4 text-pink-400" />
          </div>
          <p className="mt-2 text-2xl font-bold tracking-tight text-white tabular-nums font-mono">
            {stats.dmedCount} <span className="text-sm font-normal text-neutral-500">/ {stats.noWebsite}</span>
          </p>
          <p className="text-[11px] text-neutral-500 mt-0.5">
            {stats.noWebsite > 0 ? `${Math.round((stats.dmedCount / stats.noWebsite) * 100)}% outreach progress` : '0%'}
          </p>
        </div>
      </div>

      {/* Filter and Pipeline Bar */}
      <div className="rounded-xl border border-neutral-800 bg-neutral-900/60 p-4 space-y-4">
        {/* Main Website Filter Tabs */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-mono text-neutral-400 mr-1">Filter Leads:</span>
            <button
              onClick={() => setWebsiteFilter('NO_WEBSITE')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                websiteFilter === 'NO_WEBSITE'
                  ? 'bg-pink-600 text-white shadow-md shadow-pink-600/30'
                  : 'bg-neutral-950 text-neutral-400 hover:text-white border border-neutral-800'
              }`}
            >
              <Target className="h-3.5 w-3.5" />
              <span>🎯 No Website ({stats.noWebsite})</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-pink-900/60 text-pink-200 border border-pink-500/30">
                DM Priority
              </span>
            </button>

            <button
              onClick={() => setWebsiteFilter('ALL')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                websiteFilter === 'ALL'
                  ? 'bg-neutral-100 text-neutral-950 font-bold'
                  : 'bg-neutral-950 text-neutral-400 hover:text-white border border-neutral-800'
              }`}
            >
              All Leads ({stats.total})
            </button>

            <button
              onClick={() => setWebsiteFilter('HAS_WEBSITE')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                websiteFilter === 'HAS_WEBSITE'
                  ? 'bg-cyan-600 text-white font-bold'
                  : 'bg-neutral-950 text-neutral-400 hover:text-white border border-neutral-800'
              }`}
            >
              <Globe className="h-3.5 w-3.5" />
              <span>Has Website ({stats.hasWebsite})</span>
            </button>
          </div>

          {/* Quick search & sort */}
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-neutral-500" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search name, street, @handle..."
                className="rounded-md border border-neutral-700 bg-neutral-950 pl-8 pr-3 py-1.5 text-xs text-white placeholder-neutral-500 focus:border-emerald-500 focus:outline-none w-52"
              />
            </div>

            <select
              value={sortBy}
              onChange={(e: any) => setSortBy(e.target.value)}
              className="rounded-md border border-neutral-700 bg-neutral-950 px-2 py-1.5 text-xs text-white focus:border-emerald-500 focus:outline-none"
            >
              <option value="rating">Sort: Highest Rating</option>
              <option value="reviews">Sort: Most Reviews</option>
              <option value="name">Sort: Name A-Z</option>
            </select>
          </div>
        </div>

        {/* Pipeline Status filter chips & bulk actions */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-neutral-800/60 text-xs">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-neutral-500 font-mono text-[11px] mr-1">Pipeline:</span>
            {['ALL', ...PIPELINE_STATUSES].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2 py-1 rounded text-[11px] font-mono transition-colors ${
                  statusFilter === st
                    ? 'bg-emerald-500 text-neutral-950 font-bold'
                    : 'bg-neutral-950 text-neutral-400 hover:text-white border border-neutral-800'
                }`}
              >
                {st} {st !== 'ALL' && `(${stats.statusCounts[st] || 0})`}
              </button>
            ))}
          </div>

          {selectedIds.size > 0 && (
            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="text-pink-400 font-semibold">{selectedIds.size} selected</span>
              <span className="text-neutral-500">· Set Status:</span>
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
                <th className="p-3">Business Name & Address</th>
                <th className="p-3">Website Status</th>
                <th className="p-3">Instagram & Cold DM Outreach</th>
                <th className="p-3">Phone & Google Rating</th>
                <th className="p-3">Outreach Status</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-800/80">
              {filteredLeads.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-12 text-center text-neutral-500">
                    <Building2 className="h-8 w-8 mx-auto mb-2 opacity-30 text-neutral-400" />
                    <p className="text-sm font-medium text-neutral-300">
                      {websiteFilter === 'NO_WEBSITE'
                        ? 'No businesses found without a website in this current filter.'
                        : 'No leads match your filter criteria.'}
                    </p>
                    <p className="text-xs text-neutral-500 mt-1">
                      {websiteFilter === 'NO_WEBSITE' ? (
                        <button
                          onClick={() => setWebsiteFilter('ALL')}
                          className="text-pink-400 hover:underline font-semibold"
                        >
                          Switch to All Leads ({stats.total})
                        </button>
                      ) : (
                        'Try searching for another query or click "Find Real Leads".'
                      )}
                    </p>
                  </td>
                </tr>
              ) : (
                filteredLeads.map((lead) => {
                  const igHandle = lead.instagramHandle || `@${lead.name.toLowerCase().replace(/[^a-z0-9]/g, '')}`;
                  const igUsername = igHandle.replace(/^@/, '');
                  const igUrl = `https://www.instagram.com/${igUsername}/`;

                  return (
                    <tr
                      key={lead.id}
                      className={`hover:bg-neutral-900/80 transition-colors group ${
                        !lead.hasWebsite ? 'bg-pink-950/5' : ''
                      }`}
                    >
                      {/* Checkbox */}
                      <td className="p-3">
                        <input
                          type="checkbox"
                          checked={selectedIds.has(lead.id)}
                          onChange={() => toggleSelectOne(lead.id)}
                          className="rounded border-neutral-700 bg-neutral-950 text-pink-500"
                        />
                      </td>

                      {/* Business Entity & Real Physical Address */}
                      <td className="p-3 max-w-xs">
                        <div className="space-y-0.5">
                          <div className="font-semibold text-white flex items-center gap-1.5">
                            <span>{lead.name}</span>
                            <a
                              href={lead.placeUrl}
                              target="_blank"
                              rel="noreferrer"
                              className="text-neutral-500 hover:text-emerald-400 transition-colors"
                              title="Open place on Google Maps"
                            >
                              <ExternalLink className="h-3 w-3 inline" />
                            </a>
                          </div>
                          <div className="text-[11px] text-neutral-400">
                            <span>{lead.category}</span>
                            <span className="mx-1 text-neutral-600">·</span>
                            <span>{lead.city}</span>
                          </div>
                          <div className="text-[11px] text-neutral-400 font-mono flex items-center gap-1">
                            <MapPin className="h-3 w-3 text-neutral-500 shrink-0" />
                            <span className="truncate" title={lead.address}>
                              {lead.address}
                            </span>
                          </div>
                        </div>
                      </td>

                      {/* Website Status Badge */}
                      <td className="p-3">
                        {!lead.hasWebsite || !lead.website ? (
                          <div className="space-y-1">
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-pink-950/60 border border-pink-500/40 text-pink-300">
                              <span className="h-1.5 w-1.5 rounded-full bg-pink-400 animate-ping"></span>
                              <span>NO WEBSITE</span>
                            </span>
                            <p className="text-[10px] text-pink-400/80 font-mono">
                              High priority Instagram DM lead
                            </p>
                          </div>
                        ) : (
                          <div className="space-y-0.5">
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-neutral-900 border border-neutral-700 text-neutral-300">
                              <Globe className="h-3 w-3 text-cyan-400" />
                              <span>Has Website</span>
                            </span>
                            <div className="text-[11px] text-cyan-400 truncate max-w-[160px]">
                              <a
                                href={lead.website}
                                target="_blank"
                                rel="noreferrer"
                                className="hover:underline flex items-center gap-1 truncate"
                              >
                                <span className="truncate">{lead.website.replace('https://', '').replace('http://', '')}</span>
                                <ExternalLink className="h-2.5 w-2.5 shrink-0 opacity-70" />
                              </a>
                            </div>
                            {lead.emails && lead.emails.length > 0 && (
                              <div className="text-[10px] text-emerald-400 font-mono truncate max-w-[160px]" title={lead.emails[0]}>
                                ✉ {lead.emails[0]}
                              </div>
                            )}
                          </div>
                        )}
                      </td>

                      {/* Instagram & 1-Click Cold DM Pitch */}
                      <td className="p-3 max-w-sm">
                        <div className="space-y-1.5">
                          <div className="flex items-center gap-2">
                            <a
                              href={igUrl}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex items-center gap-1.5 text-xs font-semibold text-pink-400 hover:text-pink-300 hover:underline"
                            >
                              <Instagram className="h-3.5 w-3.5" />
                              <span>{igHandle}</span>
                              <ExternalLink className="h-2.5 w-2.5 opacity-70" />
                            </a>

                            <button
                              onClick={() => {
                                handleStatusChange(lead.id, 'DMed on Instagram');
                                window.open(igUrl, '_blank', 'noreferrer');
                              }}
                              className="text-[10px] font-mono font-medium rounded bg-pink-950/60 hover:bg-pink-900 border border-pink-500/30 text-pink-300 px-2 py-0.5 transition-colors flex items-center gap-1"
                              title="Open Instagram & mark status as DMed"
                            >
                              <Send className="h-2.5 w-2.5" />
                              <span>Open IG & Mark DMed</span>
                            </button>
                          </div>

                          {/* Quick pitch preview & copy button */}
                          {lead.instagramPitch && (
                            <div className="flex items-start gap-1.5 rounded-lg bg-neutral-950/90 border border-neutral-800/80 p-2 text-[11px] text-neutral-300">
                              <p className="line-clamp-2 leading-relaxed text-neutral-300 flex-1">
                                {lead.instagramPitch}
                              </p>
                              <button
                                onClick={() => handleCopyText(lead.instagramPitch!, `pitch_${lead.id}`)}
                                className="shrink-0 p-1 rounded bg-neutral-900 hover:bg-neutral-800 text-neutral-400 hover:text-white transition-colors border border-neutral-700"
                                title="Copy Cold DM Pitch"
                              >
                                {copiedId === `pitch_${lead.id}` ? (
                                  <Check className="h-3 w-3 text-emerald-400" />
                                ) : (
                                  <Copy className="h-3 w-3" />
                                )}
                              </button>
                            </div>
                          )}
                        </div>
                      </td>

                      {/* Phone & Rating */}
                      <td className="p-3 font-mono">
                        <div className="space-y-1">
                          {lead.phone ? (
                            <div className="flex items-center gap-1.5 text-[11px] text-neutral-300">
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
                          ) : (
                            <span className="text-[11px] text-neutral-600 italic">No phone listed</span>
                          )}

                          <div className="flex items-center gap-1 text-[11px]">
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
                            <span className="text-[10px] text-neutral-500 tabular-nums">
                              ({lead.reviewsCount})
                            </span>
                          </div>
                        </div>
                      </td>

                      {/* Pipeline Status Selector */}
                      <td className="p-3">
                        <select
                          value={lead.status}
                          onChange={(e: any) => handleStatusChange(lead.id, e.target.value)}
                          className={`rounded px-2 py-1 text-xs font-mono font-medium border ${
                            lead.status === 'DMed on Instagram'
                              ? 'bg-pink-950/60 border-pink-500/40 text-pink-300 font-bold'
                              : lead.status === 'Won'
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
                            onClick={() => setOutreachLead(lead)}
                            className="rounded p-1 text-pink-400 hover:text-white hover:bg-pink-950/60 border border-pink-500/20 transition-colors"
                            title="Open Instagram Cold DM Pitch Deck"
                          >
                            <MessageCircle className="h-3.5 w-3.5" />
                          </button>
                          <button
                            onClick={() => setSelectedLead(lead)}
                            className="rounded p-1 text-neutral-400 hover:text-white hover:bg-neutral-800 transition-colors"
                            title="View business details"
                          >
                            <Layers className="h-3.5 w-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Instagram Cold DM Pitch Deck Drawer / Modal */}
      {outreachLead && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
          <div className="w-full max-w-2xl rounded-2xl border border-pink-500/30 bg-neutral-950 p-6 shadow-2xl space-y-6">
            <div className="flex items-start justify-between border-b border-neutral-800 pb-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-pink-500/20 text-pink-400">
                    <Instagram className="h-4 w-4" />
                  </div>
                  <h3 className="text-lg font-bold text-white">Instagram Cold DM Outreach</h3>
                  {!outreachLead.hasWebsite && (
                    <span className="text-[10px] font-mono font-bold bg-pink-900/60 text-pink-200 border border-pink-500/40 px-2 py-0.5 rounded">
                      NO WEBSITE TARGET
                    </span>
                  )}
                </div>
                <p className="text-xs text-neutral-400">
                  Target: <span className="font-semibold text-white">{outreachLead.name}</span> ({outreachLead.category} in {outreachLead.city}) · {outreachLead.rating}★ ({outreachLead.reviewsCount} Google reviews)
                </p>
              </div>
              <button
                onClick={() => setOutreachLead(null)}
                className="rounded-lg p-1 text-neutral-400 hover:text-white hover:bg-neutral-900 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Business Contact summary */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 rounded-xl border border-neutral-800 bg-neutral-900/40 p-3 text-xs">
              <div>
                <span className="text-neutral-500 font-mono">Instagram Profile:</span>
                <p className="font-semibold text-pink-400 mt-0.5 flex items-center gap-1">
                  <span>{outreachLead.instagramHandle || `@${outreachLead.name.toLowerCase().replace(/[^a-z0-9]/g, '')}`}</span>
                  <a
                    href={`https://www.instagram.com/${(outreachLead.instagramHandle || outreachLead.name).replace(/[^a-zA-Z0-9_.]/g, '')}/`}
                    target="_blank"
                    rel="noreferrer"
                    className="hover:underline text-neutral-400 hover:text-white"
                  >
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </p>
              </div>
              <div>
                <span className="text-neutral-500 font-mono">Website Status:</span>
                <p className="mt-0.5 font-semibold text-pink-300">
                  {outreachLead.hasWebsite ? `Active (${outreachLead.website})` : '🚫 NO OFFICIAL WEBSITE'}
                </p>
              </div>
              <div>
                <span className="text-neutral-500 font-mono">Phone:</span>
                <p className="font-mono text-neutral-300 mt-0.5">{outreachLead.phone || 'N/A'}</p>
              </div>
            </div>

            {/* 3 Customized Pitch Options */}
            <div className="space-y-3">
              <span className="text-xs font-mono text-neutral-400 uppercase tracking-wider">
                Select Cold Pitch Angle:
              </span>

              {/* Angle 1: Lost Inquiries & Direct Mockup */}
              <div className="rounded-xl border border-neutral-800 bg-neutral-900/70 p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="flex h-5 w-5 items-center justify-center rounded-full bg-pink-500/20 text-pink-400 font-bold text-xs">1</span>
                    <span className="text-xs font-semibold text-white">Angle: Lost Bookings & Free Mockup (Highest Reply Rate)</span>
                  </div>
                  <button
                    onClick={() => {
                      const text = `Hey ${outreachLead.name} team! 👋 Came across your ${outreachLead.category} in ${outreachLead.city} with your great ${outreachLead.rating}★ reviews on Google. Noticed you guys don't have a direct website for bookings/quotes yet—you might be losing 30-40% of potential customers to competitors with websites. Would you be open to seeing a free 2-minute mock-up of what your mobile site could look like?`;
                      handleCopyText(text, 'pitch_angle_1');
                    }}
                    className="flex items-center gap-1 rounded bg-neutral-800 hover:bg-neutral-700 px-2.5 py-1 text-xs text-white transition-colors"
                  >
                    {copiedId === 'pitch_angle_1' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                    <span>{copiedId === 'pitch_angle_1' ? 'Copied Pitch!' : 'Copy Pitch'}</span>
                  </button>
                </div>
                <p className="text-xs text-neutral-300 leading-relaxed font-sans bg-neutral-950 p-2.5 rounded border border-neutral-800">
                  Hey {outreachLead.name} team! 👋 Came across your {outreachLead.category} in {outreachLead.city} with your great {outreachLead.rating}★ reviews on Google. Noticed you guys don&apos;t have a direct website for bookings/quotes yet—you might be losing 30-40% of potential customers to competitors with websites. Would you be open to seeing a free 2-minute mock-up of what your mobile site could look like?
                </p>
              </div>

              {/* Angle 2: Casual & Friendly Instagram DM */}
              <div className="rounded-xl border border-neutral-800 bg-neutral-900/70 p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="flex h-5 w-5 items-center justify-center rounded-full bg-cyan-500/20 text-cyan-400 font-bold text-xs">2</span>
                    <span className="text-xs font-semibold text-white">Angle: Casual & Compliment First</span>
                  </div>
                  <button
                    onClick={() => {
                      const text = `Hi ${outreachLead.name}! Love what you guys are doing in ${outreachLead.city}. I found you on Google Maps and wanted to check your services, but noticed you don't have an official website up yet. We build ultra-fast, high-converting mobile sites for local ${outreachLead.category} businesses that link right to your IG. Can I send over a quick free draft we made for you?`;
                      handleCopyText(text, 'pitch_angle_2');
                    }}
                    className="flex items-center gap-1 rounded bg-neutral-800 hover:bg-neutral-700 px-2.5 py-1 text-xs text-white transition-colors"
                  >
                    {copiedId === 'pitch_angle_2' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                    <span>{copiedId === 'pitch_angle_2' ? 'Copied Pitch!' : 'Copy Pitch'}</span>
                  </button>
                </div>
                <p className="text-xs text-neutral-300 leading-relaxed font-sans bg-neutral-950 p-2.5 rounded border border-neutral-800">
                  Hi {outreachLead.name}! Love what you guys are doing in {outreachLead.city}. I found you on Google Maps and wanted to check your services, but noticed you don&apos;t have an official website up yet. We build ultra-fast, high-converting mobile sites for local {outreachLead.category} businesses that link right to your IG. Can I send over a quick free draft we made for you?
                </p>
              </div>

              {/* Angle 3: Short & Direct */}
              <div className="rounded-xl border border-neutral-800 bg-neutral-900/70 p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="flex h-5 w-5 items-center justify-center rounded-full bg-emerald-500/20 text-emerald-400 font-bold text-xs">3</span>
                    <span className="text-xs font-semibold text-white">Angle: Short & Direct (Quick tap response)</span>
                  </div>
                  <button
                    onClick={() => {
                      const text = `Hey there! Noticed ${outreachLead.name} in ${outreachLead.city} doesn’t have a website linked on Google or Instagram yet. We build clean mobile sites for local businesses that turn scrollers into paying clients. Mind if I share a 60-second preview?`;
                      handleCopyText(text, 'pitch_angle_3');
                    }}
                    className="flex items-center gap-1 rounded bg-neutral-800 hover:bg-neutral-700 px-2.5 py-1 text-xs text-white transition-colors"
                  >
                    {copiedId === 'pitch_angle_3' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                    <span>{copiedId === 'pitch_angle_3' ? 'Copied Pitch!' : 'Copy Pitch'}</span>
                  </button>
                </div>
                <p className="text-xs text-neutral-300 leading-relaxed font-sans bg-neutral-950 p-2.5 rounded border border-neutral-800">
                  Hey there! Noticed {outreachLead.name} in {outreachLead.city} doesn&apos;t have a website linked on Google or Instagram yet. We build clean mobile sites for local businesses that turn scrollers into paying clients. Mind if I share a 60-second preview?
                </p>
              </div>
            </div>

            {/* Launch Instagram & update status CTA */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 border-t border-neutral-800 pt-4">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    handleStatusChange(outreachLead.id, 'DMed on Instagram');
                    const username = (outreachLead.instagramHandle || outreachLead.name).replace(/[^a-zA-Z0-9_.]/g, '');
                    window.open(`https://www.instagram.com/${username}/`, '_blank', 'noreferrer');
                  }}
                  className="flex items-center gap-2 rounded-lg bg-pink-600 hover:bg-pink-500 px-4 py-2 text-xs font-semibold text-white transition-colors shadow-lg shadow-pink-600/30"
                >
                  <Send className="h-3.5 w-3.5" />
                  <span>Launch Instagram &amp; Mark &quot;DMed&quot;</span>
                </button>

                <select
                  value={outreachLead.status}
                  onChange={(e: any) => handleStatusChange(outreachLead.id, e.target.value)}
                  className="rounded-lg border border-neutral-700 bg-neutral-900 px-3 py-2 text-xs text-white"
                >
                  {PIPELINE_STATUSES.map((st) => (
                    <option key={st} value={st}>
                      {st}
                    </option>
                  ))}
                </select>
              </div>

              <button
                onClick={() => setOutreachLead(null)}
                className="rounded-lg bg-neutral-800 hover:bg-neutral-700 px-4 py-2 text-xs font-semibold text-white transition-colors"
              >
                Close Deck
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Lead Detail Dossier Modal */}
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
                <span className="text-neutral-500 font-mono">Physical Street Address</span>
                <p className="font-medium text-white">{selectedLead.address}</p>
              </div>

              <div className="space-y-1">
                <span className="text-neutral-500 font-mono">Phone Number</span>
                <p className="font-mono text-emerald-400">{selectedLead.phone || 'N/A'}</p>
              </div>

              <div className="space-y-1">
                <span className="text-neutral-500 font-mono">Website Presence</span>
                {selectedLead.hasWebsite && selectedLead.website ? (
                  <p className="text-cyan-400 truncate">
                    <a href={selectedLead.website} target="_blank" rel="noreferrer" className="hover:underline">
                      {selectedLead.website}
                    </a>
                  </p>
                ) : (
                  <p className="text-pink-400 font-semibold font-mono">NO WEBSITE (High-Priority Prospect)</p>
                )}
              </div>

              <div className="space-y-1">
                <span className="text-neutral-500 font-mono">Instagram Profile</span>
                <p className="font-semibold text-pink-400">
                  <a
                    href={`https://www.instagram.com/${(selectedLead.instagramHandle || selectedLead.name).replace(/[^a-zA-Z0-9_.]/g, '')}/`}
                    target="_blank"
                    rel="noreferrer"
                    className="hover:underline flex items-center gap-1"
                  >
                    <span>{selectedLead.instagramHandle || `@${selectedLead.name.toLowerCase().replace(/[^a-z0-9]/g, '')}`}</span>
                    <ExternalLink className="h-3 w-3" />
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

              <div className="space-y-1">
                <span className="text-neutral-500 font-mono">Opening Hours</span>
                <p className="text-neutral-300">{selectedLead.openingHours}</p>
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

              {selectedLead.instagramPitch && (
                <div className="space-y-1 sm:col-span-2">
                  <span className="text-neutral-500 font-mono">Recommended Cold DM Pitch</span>
                  <div className="rounded-lg bg-neutral-900 border border-neutral-800 p-3 text-neutral-300 flex items-start justify-between gap-2">
                    <p className="leading-relaxed">{selectedLead.instagramPitch}</p>
                    <button
                      onClick={() => handleCopyText(selectedLead.instagramPitch!, 'modal_pitch')}
                      className="shrink-0 p-1 rounded bg-neutral-800 text-neutral-400 hover:text-white"
                    >
                      {copiedId === 'modal_pitch' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                    </button>
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-center justify-between border-t border-neutral-800 pt-4">
              <a
                href={selectedLead.placeUrl}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400 hover:text-emerald-300"
              >
                <span>View Real Google Maps Listing</span>
                <ExternalLink className="h-3.5 w-3.5" />
              </a>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    setOutreachLead(selectedLead);
                    setSelectedLead(null);
                  }}
                  className="rounded-lg bg-pink-600 hover:bg-pink-500 px-3 py-1.5 text-xs font-semibold text-white transition-colors"
                >
                  Open Instagram Outreach
                </button>
                <button
                  onClick={() => setSelectedLead(null)}
                  className="rounded-lg bg-neutral-800 hover:bg-neutral-700 px-3 py-1.5 text-xs font-semibold text-white transition-colors"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
