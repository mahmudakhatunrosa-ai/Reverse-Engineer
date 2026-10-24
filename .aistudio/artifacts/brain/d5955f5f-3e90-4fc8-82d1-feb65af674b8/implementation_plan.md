# Implementation Plan: Google Maps Scraper Kit Integration

Replicate and integrate the core features of [Mahanaicoach/google-maps-scraper-kit](https://github.com/Mahanaicoach/google-maps-scraper-kit) into the platform. This transforms the application with a local, keyless-first Google Maps lead extraction engine, automated website contact/social enrichment, an interactive lead management pipeline, clean CSV/JSON exports, and FastMCP server tools for Claude/Cursor/Windsurf.

## User Review Required

> [!IMPORTANT]
> The scraper operates out-of-the-box without requiring Google Cloud / Maps API billing keys by leveraging local web extraction and website contact crawling. An optional Google Maps Platform API key input is also provided for high-throughput enterprise batch querying.

- **Data Privacy & Local Execution**: Scraped leads are stored in memory and client state for zero data leakage, with instant one-click CSV/JSON export.
- **Contact Enrichment**: When business websites are found, the scraper automatically crawls the target homepage and contact pages to harvest emails, phone numbers, and social links (LinkedIn, Facebook, Instagram, Twitter/X, YouTube).

---

## Proposed Changes

### 1. Scraper & Enrichment Backend API Route
#### `app/api/gmaps-scraper/route.ts`
- Implement robust server-side Google Maps scraper handler supporting:
  - Query parameters: `query` (e.g. "plumbers in Phoenix, AZ"), `city`, `limit` (depth), `enrichContacts` (boolean).
  - Dual extraction: Local web extractor with resilient structure parsing + optional Places API fallback if custom key supplied.
  - Automated Website Contact Enrichment: Crawls discovered business websites using lightweight HTML extraction to discover:
    - Business email addresses (`mailto:` and regex patterns)
    - Social links (LinkedIn, Twitter/X, Instagram, Facebook, GitHub, YouTube)
    - Secondary phone numbers
  - Formats output with standard lead schema matching `google-maps-scraper-kit`:
    - `id`, `name`, `category`, `address`, `city`, `state`, `phone`, `website`, `email`, `rating`, `reviewCount`, `socials`, `status`, `scrapedAt`.

---

### 2. Interactive Google Maps Scraper Dashboard
#### `components/GoogleMapsScraper.tsx`
Create a high-density, production-grade Lead Generation & Scraper interface:
- **Search & Configuration Console**:
  - Keyword and City inputs with quick presets ("Coffee shops in Austin, TX", "Plumbers in Phoenix, AZ", "Cybersecurity consultants in SF", "Dentists in Miami, FL").
  - Scraping depth slider (5, 10, 20, 50 leads).
  - Toggles for contact enrichment (emails & social profiles) and live log streaming.
- **Live Terminal & Progress Feed**:
  - Real-time step-by-step extraction logs (query dispatched, places parsed, websites crawled, emails extracted).
- **Interactive Lead Status Pipeline**:
  - Leads categorized into actionable stages: `New` -> `Contacted` -> `Qualified` -> `Disqualified` -> `Won`.
  - Filter by pipeline status, keyword search, rating thresholds, and verified email existence.
  - Quick inline status updating and lead editing.
- **Export & Action Suite**:
  - **Export CSV**: Generates RFC 4180-compliant CSV matching `google-maps-scraper-kit` output.
  - **Export JSON**: Formatted raw JSON for API & CRM ingestion.
  - **Copy to Clipboard**: One-click formatted list for quick pasting into outreach tools.

---

### 3. FastMCP Server & Python Toolkit Integration
#### `lib/server-files.ts` & `mcp_server/server.py`
- Add `scrape_google_maps_leads` tool to the FastMCP Python server definition:
  - Tool signature accepting `query: str, city: Optional[str], limit: int = 10, enrich_contacts: bool = True`.
  - Enables AI agents (Claude Desktop, Claude Code, Cursor, Windsurf) to execute natural-language lead generation prompts (e.g., *"Scrape 15 roofers in Denver and give me their emails and phone numbers"*).
- Add `scripts/scrape.py` and `docker-compose.yml` to the downloadable server bundle matching the original `Mahanaicoach/google-maps-scraper-kit` repository structure.

---

### 4. Navigation & Page Integration
#### `components/Navbar.tsx` & `app/page.tsx`
- Add dedicated navigation tab: **"Google Maps Scraper"** with MapPin icon.
- Update hero badge and statistics to showcase Google Maps Scraper Kit capabilities.
- Mount `GoogleMapsScraper` component in the main page router.

#### `components/ToolPlayground.tsx`
- Add `scrape_google_maps_leads` preset and tool runner in the Live Tool Playground so users can test queries directly alongside binary analysis tools.

---

## Verification Plan

### Automated Verification
1. **Compilation Check**:
   - Run `compile_applet` to ensure TypeScript types, Next.js routes, and imports compile with 0 errors.
2. **Lint Validation**:
   - Run `lint_applet` to confirm compliance with ESLint rules.

### Functional Verification
1. **Scraping & Lead Generation**:
   - Trigger a search query (e.g., "Coffee shops in Austin, TX").
   - Confirm leads populate with Name, Address, Phone, Website, Rating, and Review Count.
2. **Website Contact Enrichment**:
   - Verify that website scraping extracts email addresses and social links (LinkedIn, Instagram, etc.).
3. **Pipeline Management & Exports**:
   - Update a lead's status from `New` to `Qualified`.
   - Download CSV and JSON exports and verify data column fidelity.
