# HexStrike AI FastMCP Server (24/7 on Render)

Production-ready Model Context Protocol (MCP) server for [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) reverse engineering, disassembling, decompiling, security mitigations, and binary intelligence.

---

## Architecture Overview

```
Claude Desktop / Claude Custom MCP / Cursor / Windsurf
               │
               ▼ (SSE / HTTP Transport)
┌──────────────────────────────────────────────────────┐
│  Render Web Service (Running 24/7)                   │
│  FastMCP + FastAPI + Uvicorn                         │
│  • Tools: Disassembly, Headers, Entropy, Strings,   │
│           Mitigations, Pseudocode, Packer Detection  │
└──────────────────────────────────┬───────────────────┘
                                   │ (Optional Backend Relay)
                                   ▼
┌──────────────────────────────────────────────────────┐
│  HexStrike AI Core Engine (150+ Security Tools)      │
│  https://github.com/0x4m4/hexstrike-ai               │
└──────────────────────────────────────────────────────┘
```

---

## 1. Step-by-Step Render Setup (24/7 Background Running)

### Option A: Standard Render Web Service Setup (Recommended)

1. **Push this folder to a GitHub Repository**:
   ```bash
   git init
   git add .
   git commit -m "HexStrike FastMCP Server"
   git remote add origin https://github.com/YOUR_USERNAME/hexstrike-mcp.git
   git branch -M main
   git push -u origin main
   ```

2. **Open Render Dashboard**:
   - Go to [https://dashboard.render.com](https://dashboard.render.com)
   - Click **New +** → **Web Service**
   - Connect your newly created GitHub repository `hexstrike-mcp`

3. **Configure the Service Settings**:
   - **Name**: `hexstrike-fastmcp` (or your preferred name)
   - **Region**: Choose the closest region (e.g. Oregon, Frankfurt, Singapore)
   - **Language / Runtime**: `Python 3` (or `Docker` if using the included Dockerfile)
   - **Branch**: `main`
   - **Build Command**:
     ```bash
     pip install --upgrade pip && pip install -r requirements.txt
     ```
   - **Start Command**:
     ```bash
     uvicorn server:app --host 0.0.0.0 --port $PORT
     ```
   - **Plan**: `Free` (or `Starter` $7/mo for guaranteed zero-sleep 24/7 background uptime)

4. **Add Health Check & Environment Variables**:
   - Click **Advanced**:
     - **Health Check Path**: `/health`
     - **Auto-Deploy**: `Yes`
   - Add Environment Variables:
     - `PYTHON_VERSION`: `3.11.9`
     - `LOG_LEVEL`: `info`
     - `HEXSTRIKE_BACKEND_URL`: `http://localhost:8888` (optional)

5. **Deploy**:
   - Click **Create Web Service**. Render will build and deploy your container.
   - Once deployed, your URL will be: `https://hexstrike-fastmcp.onrender.com`

---

## 2. Preventing Free-Tier Sleep (Keeping it 24/7 Warm)

On Render's Free tier, services spin down after 15 minutes of inactivity. To keep your MCP server active 24/7 for Claude at zero cost:

1. **Option 1: Free Uptime Robot / Cron-Job.org Ping (Easiest)**
   - Create a free account at [UptimeRobot.com](https://uptimerobot.com) or [cron-job.org](https://cron-job.org)
   - Add an HTTP monitor to: `https://YOUR-APP.onrender.com/health`
   - Interval: Every **10 minutes**
   - This keeps your server awake 24/7 without cold starts.

2. **Option 2: Run the included keep-alive script**:
   ```bash
   python render_keepalive.py https://YOUR-APP.onrender.com
   ```

3. **Option 3: Render Starter Plan ($7/mo)**:
   - Persistent RAM/CPU with zero sleep.

---

## 3. Connecting to Claude Custom MCP Server

### A. Claude Desktop Integration (`claude_desktop_config.json`)

On your computer, open:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Add the following configuration (replace with your Render URL):

```json
{
  "mcpServers": {
    "hexstrike-reverse-engineering": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://YOUR-APP-NAME.onrender.com/sse"
      ]
    }
  }
}
```

*Note: `mcp-remote` comes from `npx mcp-remote` and seamlessly bridges Claude Desktop's local stdio MCP protocol with your remote Render SSE server!*

### B. Cursor Integration (`~/.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "url": "https://YOUR-APP-NAME.onrender.com/sse",
      "transport": "sse"
    }
  }
}
```

### C. Windsurf Integration (`~/.codeium/windsurf/mcp_config.json`)

```json
{
  "mcpServers": {
    "hexstrike-ai": {
      "serverUrl": "https://YOUR-APP-NAME.onrender.com/sse"
    }
  }
}
```

---

## 4. Testing Your MCP Deployment

Run the test client locally to confirm endpoints before opening Claude:

```bash
python test_client.py https://YOUR-APP-NAME.onrender.com
```

Output:
```
[*] Testing HexStrike FastMCP server at: https://YOUR-APP-NAME.onrender.com
[+] Health check (https://YOUR-APP-NAME.onrender.com/health): HTTP 200
[+] Root endpoint (https://YOUR-APP-NAME.onrender.com/): HTTP 200
    Server: HexStrike AI FastMCP Server
    Tools:  inspect_binary_headers, disassemble_machine_code, analyze_entropy_and_packers, extract_strings_and_secrets, audit_security_mitigations, decompile_function_pseudocode, hexstrike_backend_relay
```

---

## 5. Available Reverse Engineering Tools in Claude

Once connected to Claude, simply prompt:
- *"Claude, disassemble this hex bytecode: 4889e5b801000000c3 using HexStrike."*
- *"Check the entropy of this payload to see if it is packed with UPX or Themida."*
- *"Audit the security mitigations on this binary header (ASLR, NX, Stack Canary)."*
- *"Extract all suspicious URLs, IPs, and API tokens from this base64 dump."*
- *"Decompile this assembly into readable C pseudocode."*
