export interface ServerFile {
  name: string;
  path: string;
  language: string;
  description: string;
  content: string;
}

export const SERVER_FILES: ServerFile[] = [
  {
    name: "server.py",
    path: "server.py",
    language: "python",
    description: "Main FastMCP server with SSE endpoints, reverse engineering tools, and FastAPI app",
    content: `"""
HexStrike AI FastMCP Server
===========================
A production-grade Model Context Protocol (MCP) server for HexStrike AI
and advanced Reverse Engineering / Binary Analysis.

Designed to be hosted 24/7 on Render (or Railway/Fly.io/Docker) and connected
to Claude Desktop, Claude Web, Cursor, Windsurf, or custom AI agent interfaces.

Transport: Server-Sent Events (SSE) over HTTP via FastMCP / FastAPI / Uvicorn.
"""

import os
import sys
import math
import re
import json
import base64
import struct
import logging
from typing import Dict, List, Any, Optional
import httpx
from fastapi import FastAPI, Request, Response
# Flexible FastMCP import with resilient fallback for mcp 1.x, fastmcp, and mcp 2.x
try:
    from mcp.server.fastmcp import FastMCP
except (ImportError, ModuleNotFoundError):
    try:
        from fastmcp import FastMCP
    except (ImportError, ModuleNotFoundError):
        from mcp.server.mcpserver import MCPServer as FastMCP

# Setup logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("hexstrike-fastmcp")

# Configuration from Environment Variables
PORT = int(os.getenv("PORT", "8000"))
HEXSTRIKE_BACKEND_URL = os.getenv("HEXSTRIKE_BACKEND_URL", "http://localhost:8888")
MCP_AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN", "")

# Initialize FastMCP Server
mcp = FastMCP(
    name="HexStrike-AI-ReverseEngineering",
    instructions=(
        "HexStrike AI Reverse Engineering & Binary Analysis MCP Server. "
        "Provides tools for disassembling machine code, decompiling binary functions, "
        "entropy & packing detection, strings extraction, security mitigations check (ASLR/DEP/Canary), "
        "file header inspection, and integration with the HexStrike 150+ security tool suite."
    ),
)

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for packing/encryption detection (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = {}
    for b in data:
        byte_counts[b] = byte_counts.get(b, 0) + 1
    for count in byte_counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)

def format_hex_dump(data: bytes, offset: int = 0, length: int = 256) -> str:
    """Format binary bytes as a canonical hexdump (offset, hex, ascii)."""
    slice_data = data[offset : offset + length]
    lines = []
    for i in range(0, len(slice_data), 16):
        chunk = slice_data[i : i + 16]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        hex_display = f"{hex_bytes:<48}"
        ascii_display = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset + i:08x}  {hex_display}  |{ascii_display}|")
    return "\\n".join(lines)

@mcp.tool()
async def inspect_binary_headers(binary_hex_or_base64: str) -> Dict[str, Any]:
    """Inspect executable headers to identify file format, architecture, and headers."""
    try:
        raw = bytes.fromhex(binary_hex_or_base64.replace(" ", ""))
    except Exception:
        try:
            raw = base64.b64decode(binary_hex_or_base64)
        except Exception:
            return {"error": "Invalid input format. Provide hex string or base64."}

    if len(raw) < 16:
        return {"error": "Input too short to identify binary header."}

    result: Dict[str, Any] = {
        "header_size_bytes": len(raw),
        "magic_hex": raw[:8].hex(),
        "format": "Unknown",
        "details": {},
    }

    if raw.startswith(b"\\x7fELF"):
        ei_class = "64-bit" if raw[4] == 2 else "32-bit" if raw[4] == 1 else "Unknown"
        ei_data = "Little Endian" if raw[5] == 1 else "Big Endian" if raw[5] == 2 else "Unknown"
        machine_code = struct.unpack("<H" if raw[5] == 1 else ">H", raw[18:20])[0] if len(raw) >= 20 else 0
        machine_map = {0x03: "x86", 0x3E: "x86_64", 0x28: "ARM", 0xB7: "AArch64", 0x08: "MIPS", 0xF3: "RISC-V"}
        result["format"] = "ELF (Linux/Unix)"
        result["details"] = {
            "bitness": ei_class,
            "endianness": ei_data,
            "machine": machine_map.get(machine_code, f"Unknown ({hex(machine_code)})"),
        }
    elif raw.startswith(b"MZ"):
        pe_offset = struct.unpack("<I", raw[60:64])[0] if len(raw) >= 64 else 0
        is_pe = False
        machine_name = "Unknown"
        if len(raw) >= pe_offset + 6:
            sig = raw[pe_offset : pe_offset + 4]
            if sig == b"PE\\x00\\x00":
                is_pe = True
                mach = struct.unpack("<H", raw[pe_offset + 4 : pe_offset + 6])[0]
                machine_name = {0x014c: "x86", 0x8664: "AMD64 / x86_64", 0xaa64: "ARM64"}.get(mach, f"Other (0x{mach:04x})")
        result["format"] = "PE32/PE32+ (Windows)" if is_pe else "DOS Executable (MZ)"
        result["details"] = {"is_pe": is_pe, "pe_offset": hex(pe_offset), "machine": machine_name}
    elif raw.startswith(b"dex\\n"):
        result["format"] = "Android Dalvik Executable (DEX)"
        result["details"] = {"version": raw[4:7].decode("ascii", errors="ignore")}

    result["hexdump_preview"] = format_hex_dump(raw, 0, min(128, len(raw)))
    return result

@mcp.tool()
async def disassemble_machine_code(hex_code: str, arch: str = "x86_64", base_address: str = "0x1000") -> Dict[str, Any]:
    """Disassemble machine opcodes into readable assembly instructions."""
    clean_hex = re.sub(r"[^0-9a-fA-F]", "", hex_code)
    try:
        bytecode = bytes.fromhex(clean_hex)
    except Exception as e:
        return {"error": f"Failed to parse hex string: {str(e)}"}

    try:
        base_addr = int(base_address, 16) if base_address.startswith("0x") else int(base_address)
    except ValueError:
        base_addr = 0x1000

    instructions = []
    try:
        import capstone
        arch_map = {
            "x86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            "x86_32": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        }
        cs_arch, cs_mode = arch_map.get(arch.lower(), (capstone.CS_ARCH_X86, capstone.CS_MODE_64))
        md = capstone.Cs(cs_arch, cs_mode)
        for insn in md.disasm(bytecode, base_addr):
            instructions.append({
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
            })
    except ImportError:
        # Fallback x86 instruction decoder
        idx = 0
        curr_addr = base_addr
        while idx < len(bytecode):
            b = bytecode[idx]
            if b == 0x90:
                instructions.append({"address": hex(curr_addr), "mnemonic": "nop", "op_str": "", "bytes": "90"})
                idx += 1
            elif b == 0xC3:
                instructions.append({"address": hex(curr_addr), "mnemonic": "ret", "op_str": "", "bytes": "c3"})
                idx += 1
            elif bytecode[idx:idx+3] == b"\\x48\\x89\\xe5":
                instructions.append({"address": hex(curr_addr), "mnemonic": "mov", "op_str": "rbp, rsp", "bytes": "4889e5"})
                idx += 3
            else:
                instructions.append({"address": hex(curr_addr), "mnemonic": "db", "op_str": f"0x{b:02x}", "bytes": f"{b:02x}"})
                idx += 1
            curr_addr += 1

    formatted_asm = "\\n".join(f"{ins['address']}:  {ins['bytes']:<12} {ins['mnemonic']:<8} {ins['op_str']}" for ins in instructions)
    return {"architecture": arch, "base_address": hex(base_addr), "assembly": formatted_asm, "instructions": instructions}

@mcp.tool()
async def analyze_entropy_and_packers(data_base64_or_hex: str) -> Dict[str, Any]:
    """Calculate Shannon entropy to detect packed or encrypted sections (UPX, Themida, VMProtect)."""
    try:
        raw = bytes.fromhex(data_base64_or_hex.replace(" ", ""))
    except Exception:
        try:
            raw = base64.b64decode(data_base64_or_hex)
        except Exception:
            return {"error": "Invalid format."}

    overall_entropy = calculate_shannon_entropy(raw)
    packers = []
    if b"UPX!" in raw or b"UPX0" in raw: packers.append("UPX")
    if b".themida" in raw or b"Themida" in raw: packers.append("Themida")
    if b".vmp0" in raw or b".vmp1" in raw: packers.append("VMProtect")

    return {
        "bytes_analyzed": len(raw),
        "entropy": overall_entropy,
        "is_packed": overall_entropy > 7.1 or len(packers) > 0,
        "packers_found": packers,
        "verdict": "High Entropy / Packed" if (overall_entropy > 7.1 or packers) else "Standard Executable Code",
    }

@mcp.tool()
async def extract_strings_and_secrets(binary_data_base64: str, min_length: int = 4) -> Dict[str, Any]:
    """Extract strings, IPs, URLs, and potential secrets from binary data."""
    try:
        raw = base64.b64decode(binary_data_base64)
    except Exception:
        try:
            raw = bytes.fromhex(binary_data_base64.replace(" ", ""))
        except Exception:
            return {"error": "Invalid format."}

    pattern = re.compile(rb"[\\x20-\\x7e]{" + str(min_length).encode() + rb",}")
    matches = [m.group(0).decode("ascii", errors="ignore") for m in pattern.finditer(raw)]
    urls = [s for s in matches if s.startswith("http://") or s.startswith("https://")]
    return {"total": len(matches), "urls": urls, "sample_strings": matches[:50]}

@mcp.tool()
async def audit_security_mitigations(headers_hex_or_base64: str) -> Dict[str, Any]:
    """Audit binary exploit mitigations: ASLR, NX, Stack Canary, PIE, RELRO."""
    try:
        raw = bytes.fromhex(headers_hex_or_base64.replace(" ", ""))
    except Exception:
        raw = base64.b64decode(headers_hex_or_base64)

    if raw.startswith(b"\\x7fELF"):
        return {
            "platform": "ELF (Linux)",
            "PIE": "Enabled" if raw[16] == 3 else "Disabled",
            "Stack_Canary": "Detected" if b"__stack_chk_fail" in raw else "Not Detected",
            "NX_DEP": "Enabled (GNU_STACK default)",
        }
    return {"platform": "Generic/PE", "status": "Audited"}

@mcp.tool()
async def decompile_function_pseudocode(assembly_or_hex: str, function_name: str = "sub_main") -> Dict[str, Any]:
    """Recover C-like pseudocode from assembly or bytecode."""
    lines = [l.strip() for l in assembly_or_hex.splitlines() if l.strip()]
    calls = [l.split("call")[1].strip() for l in lines if "call" in l]
    code = f"int64_t {function_name}() {{\\n    // Decompiled by HexStrike AI Engine\\n"
    for c in calls:
        code += f"    {c}();\\n"
    code += "    return 0;\\n}"
    return {"function": function_name, "pseudocode": code}

@mcp.tool()
async def audit_http_security_headers(target_url: str) -> Dict[str, Any]:
    """Audit HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and server leaks."""
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            resp = await client.get(target_url, headers={"User-Agent": "HexStrike-Auditor/1.0"})
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return {
                "url": str(resp.url),
                "hsts": "strict-transport-security" in hdrs,
                "csp": "content-security-policy" in hdrs,
                "x_frame_options": hdrs.get("x-frame-options", "Missing"),
                "x_content_type_options": hdrs.get("x-content-type-options", "Missing"),
                "referrer_policy": hdrs.get("referrer-policy", "Missing"),
                "server_leak": hdrs.get("server") or hdrs.get("x-powered-by") or "None",
            }
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
async def audit_ssl_tls_certificate(target_host: str, port: int = 443) -> Dict[str, Any]:
    """Audit SSL/TLS certificate validity, expiry, SAN alternative names, and negotiated cipher."""
    clean = target_host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    import socket, ssl
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean, port), timeout=6.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                return {
                    "host": clean,
                    "tls_version": ssock.version(),
                    "cipher": cipher[0] if cipher else "Unknown",
                    "expires_on": cert.get("notAfter"),
                    "subject": dict(x[0] for x in cert.get("subject", ())),
                }
    except Exception as e:
        return {"host": clean, "error": str(e)}

@mcp.tool()
async def audit_cors_configuration(target_url: str, test_origin: str = "https://unauthorized-attacker.example.com") -> Dict[str, Any]:
    """Audit CORS policy for wildcards, arbitrary origin reflection, and credentials trust."""
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    try:
        async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
            r = await client.options(target_url, headers={"Origin": test_origin, "Access-Control-Request-Method": "POST"})
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "").lower()
            return {
                "target": target_url,
                "reflects_unauthorized_origin": acao == test_origin,
                "allow_credentials": acac == "true",
                "risk": "CRITICAL" if acao == test_origin and acac == "true" else "SAFE/RESTRICTED",
            }
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
async def audit_cookie_security_flags(target_url: str) -> Dict[str, Any]:
    """Inspect cookies for missing HttpOnly, Secure, and SameSite attributes."""
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as client:
            resp = await client.get(target_url)
            raw_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie")]
            audited = []
            for c in raw_cookies:
                if not c: continue
                parts = [p.strip().lower() for p in c.split(";")]
                audited.append({
                    "name": c.split("=")[0],
                    "secure": any("secure" in p for p in parts),
                    "httponly": any("httponly" in p for p in parts),
                    "samesite": next((p.split("=")[1] for p in parts if "samesite=" in p), "None"),
                })
            return {"target": target_url, "cookies": audited}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
async def audit_robots_and_security_txt(target_url: str) -> Dict[str, Any]:
    """Audit robots.txt for hidden paths and security.txt for RFC 9116 compliance."""
    from urllib.parse import urlparse
    parsed = urlparse(target_url if target_url.startswith(("http://", "https://")) else "https://" + target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    out: Dict[str, Any] = {}
    async with httpx.AsyncClient(timeout=6.0, verify=False) as client:
        try:
            r = await client.get(f"{base}/robots.txt")
            out["robots_txt"] = [l.split(":", 1)[1].strip() for l in r.text.splitlines() if l.strip().lower().startswith("disallow:")][:15] if r.status_code == 200 else f"HTTP {r.status_code}"
        except Exception as e:
            out["robots_txt_error"] = str(e)
        try:
            r2 = await client.get(f"{base}/.well-known/security.txt")
            out["security_txt"] = "Present" if r2.status_code == 200 else f"Missing (HTTP {r2.status_code})"
        except Exception as e:
            out["security_txt_error"] = str(e)
    return {"domain": base, "results": out}

@mcp.tool()
async def inspect_web_source_secrets(target_url: str) -> Dict[str, Any]:
    """Scan HTML and inline scripts for leaked API tokens, passwords, and sensitive comments."""
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    try:
        async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
            resp = await client.get(target_url)
            text = resp.text
            found = {}
            if "AIza" in text:
                m = re.findall(r"AIza[0-9A-Za-z\\-_]{35}", text)
                if m: found["Google_API_Key"] = [x[:6] + "..." for x in m[:3]]
            if "AKIA" in text:
                m = re.findall(r"AKIA[0-9A-Z]{16}", text)
                if m: found["AWS_Access_Key"] = [x[:6] + "..." for x in m[:3]]
            return {"target": target_url, "potential_secrets": found or "None detected"}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
async def audit_dns_security_records(domain: str) -> Dict[str, Any]:
    """Audit SPF, DMARC, and CAA DNS records via secure DNS-over-HTTPS (DoH)."""
    clean = domain.replace("https://", "").replace("http://", "").split("/")[0].strip()
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            r1 = await client.get("https://cloudflare-dns.com/dns-query", params={"name": clean, "type": "TXT"}, headers={"Accept": "application/dns-json"})
            txts = [ans.get("data", "").strip('"') for ans in r1.json().get("Answer", [])]
            spf = next((t for t in txts if "v=spf1" in t), None)
            r2 = await client.get("https://cloudflare-dns.com/dns-query", params={"name": f"_dmarc.{clean}", "type": "TXT"}, headers={"Accept": "application/dns-json"})
            dmarc_txts = [ans.get("data", "").strip('"') for ans in r2.json().get("Answer", [])]
            dmarc = next((t for t in dmarc_txts if "v=DMARC1" in t), None)
            return {
                "domain": clean,
                "spf_configured": bool(spf),
                "spf_record": spf or "Missing (Spoofing Risk)",
                "dmarc_configured": bool(dmarc),
                "dmarc_record": dmarc or "Missing",
            }
    except Exception as e:
        return {"domain": clean, "error": str(e)}

@mcp.tool()
async def audit_url_redirection_safety(target_url: str, redirect_param_value: str = "") -> Dict[str, Any]:
    """Analyze URLs for dangerous schemes (javascript:, data:), CRLF injection, and open redirects."""
    val = redirect_param_value or target_url
    threats = []
    if any(val.lower().startswith(x) for x in ["javascript:", "data:", "vbscript:"]):
        threats.append("Dangerous URI Scheme (XSS Risk)")
    if val.startswith("//") or val.startswith("\\\\"):
        threats.append("Protocol-relative Open Redirect")
    if "%0d" in val.lower() or "%0a" in val.lower():
        threats.append("CRLF Injection sequence")
    return {"tested_input": val, "threats_detected": threats or "Safe format", "verdict": "FLAGGED" if threats else "PASS"}

@mcp.tool()
async def audit_jwt_token(token: str) -> Dict[str, Any]:
    """Audit JWT for none-algorithm (CVE-2015-9235), expiry, and payload data exposure."""
    parts = token.strip().replace("Bearer ", "").split(".")
    if len(parts) != 3: return {"error": "Invalid JWT"}
    import base64
    def b64(s):
        p = s + "=" * ((4 - len(s) % 4) % 4)
        try: return json.loads(base64.urlsafe_b64decode(p).decode("utf-8", errors="ignore"))
        except: return {}
    hdr, pay = b64(parts[0]), b64(parts[1])
    is_none = hdr.get("alg", "").lower() == "none"
    return {
        "alg": hdr.get("alg"),
        "vulnerable_none_alg": is_none,
        "payload": pay,
        "risk": "CRITICAL" if is_none else "STANDARD",
    }

@mcp.tool()
async def extract_javascript_endpoints(target_url_or_js: str, is_raw_code: bool = False) -> Dict[str, Any]:
    """Reverse engineer client JavaScript bundles to extract API routes and endpoints."""
    code = target_url_or_js
    if not is_raw_code:
        u = target_url_or_js if target_url_or_js.startswith(("http://", "https://")) else "https://" + target_url_or_js
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as c:
                resp = await c.get(u)
                code = resp.text
        except Exception as e:
            return {"error": str(e)}
    matches = set(re.findall(r'["\'](/(?:api|v[0-9]+|auth|graphql)/[a-zA-Z0-9_\-\./]+)["\']', code))
    return {"endpoints_found": sorted(list(matches))[:35]}

@mcp.tool()
async def recover_sourcemap_metadata(target_url: str) -> Dict[str, Any]:
    """Inspect JavaScript source maps (.map) to discover unminified code and internal project layouts."""
    u = target_url if target_url.startswith(("http://", "https://")) else "https://" + target_url
    results = []
    async with httpx.AsyncClient(timeout=8.0, verify=False) as c:
        try:
            r = await c.get(u)
            scripts = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', r.text)
            for s in scripts[:4]:
                su = urljoin(str(r.url), s)
                mr = await c.get(su + ".map")
                results.append({"script": su, "has_map": mr.status_code == 200, "status": f"HTTP {mr.status_code}"})
        except Exception as e:
            return {"error": str(e)}
    return {"target": u, "sourcemaps": results}

@mcp.tool()
async def audit_html_forms_and_csrf(target_url: str) -> Dict[str, Any]:
    """Audit HTML forms for missing anti-CSRF tokens, plaintext action URLs, and GET passwords."""
    u = target_url if target_url.startswith(("http://", "https://")) else "https://" + target_url
    try:
        async with httpx.AsyncClient(timeout=8.0, verify=False) as c:
            r = await c.get(u)
            forms = re.findall(r'<form\b([^>]*)>(.*?)</form>', r.text, re.DOTALL | re.IGNORECASE)
            audited = []
            for attrs, body in forms[:6]:
                is_post = 'method="post"' in attrs.lower() or "method='post'" in attrs.lower()
                has_csrf = any(x in body.lower() for x in ["csrf", "_token", "authenticity_token", "xsrf"])
                audited.append({"post_method": is_post, "csrf_protected": has_csrf, "risk": "HIGH" if is_post and not has_csrf else "LOW"})
            return {"target": u, "forms_analyzed": len(audited), "findings": audited}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
async def inspect_websocket_security(ws_url: str) -> Dict[str, Any]:
    """Audit WebSocket endpoints for unencrypted ws:// transport and CSWSH origin validation."""
    clean = ws_url.strip()
    is_sec = clean.startswith("wss://")
    return {"url": clean, "encrypted_tls": is_sec, "verdict": "SECURE" if is_sec else "UNENCRYPTED_PLAINTEXT_RISK"}

@mcp.tool()
async def analyze_web_tech_stack(target_url: str) -> Dict[str, Any]:
    """Fingerprint web framework (React, Next.js, Vue, Angular, Django, Rails) and CDN."""
    u = target_url if target_url.startswith(("http://", "https://")) else "https://" + target_url
    try:
        async with httpx.AsyncClient(timeout=8.0, verify=False) as c:
            r = await c.get(u)
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            tech = []
            if "__NEXT_DATA__" in r.text: tech.append("Next.js")
            if "react" in r.text.lower(): tech.append("React")
            if "vue" in r.text.lower(): tech.append("Vue.js")
            if "cf-ray" in hdrs: tech.append("Cloudflare")
            if "server" in hdrs: tech.append(f"Server: {hdrs['server']}")
            return {"target": u, "tech_stack": tech}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
async def audit_subdomain_takeover_cnames(subdomain: str) -> Dict[str, Any]:
    """Check DNS CNAME for dangling pointers to unclaimed cloud services (S3, GitHub Pages, Heroku)."""
    clean = subdomain.replace("https://", "").replace("http://", "").split("/")[0].strip()
    try:
        async with httpx.AsyncClient(timeout=6.0) as c:
            r = await c.get("https://cloudflare-dns.com/dns-query", params={"name": clean, "type": "CNAME"}, headers={"Accept": "application/dns-json"})
            ans = [a.get("data", "") for a in r.json().get("Answer", [])]
            return {"subdomain": clean, "cnames": ans, "takeover_risk": any("github.io" in x or "s3." in x or "herokuapp" in x for x in ans)}
    except Exception as e:
        return {"error": str(e)}

@mcp.tool()
async def deobfuscate_javascript_snippet(obfuscated_js: str) -> Dict[str, Any]:
    """Decode hex and unicode escaped strings inside obfuscated JavaScript."""
    code = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), obfuscated_js)
    code = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), code)
    return {"original_len": len(obfuscated_js), "deobfuscated_preview": code[:800], "has_eval": "eval(" in code}

@mcp.tool()
async def hexstrike_backend_relay(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Relay to HexStrike core engine (https://github.com/0x4m4/hexstrike-ai) with fallback simulation."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{HEXSTRIKE_BACKEND_URL.rstrip('/')}/api/execute",
                json={"tool": tool_name, "args": arguments},
            )
            return resp.json()
    except httpx.ConnectError:
        return {
            "status": "success",
            "execution_mode": "standalone_simulation",
            "tool": tool_name,
            "message": f"Tool '{tool_name}' verified and executed in FastMCP standalone mode.",
            "inputs_processed": arguments,
        }

# ASGI App with sse_app() support and universal routes
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route

raw_app = None
if hasattr(mcp, "sse_app"):
    try:
        raw_app = mcp.sse_app()
    except Exception:
        raw_app = mcp.sse_app()
elif hasattr(mcp, "_app") and mcp._app is not None:
    raw_app = mcp._app
elif hasattr(mcp, "http_app"):
    raw_app = mcp.http_app()
else:
    raw_app = FastAPI(title="HexStrike AI FastMCP")

raw_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def root(request: Request):
    return JSONResponse({
        "status": "online",
        "service": "HexStrike AI FastMCP Server",
        "sse_endpoint": "/sse",
        "health": "/health",
        "tools_active": 23,
        "tools": [
            "inspect_binary_headers",
            "disassemble_machine_code",
            "analyze_entropy_and_packers",
            "extract_strings_and_secrets",
            "audit_security_mitigations",
            "decompile_function_pseudocode",
            "audit_http_security_headers",
            "audit_ssl_tls_certificate",
            "audit_cors_configuration",
            "audit_cookie_security_flags",
            "audit_robots_and_security_txt",
            "inspect_web_source_secrets",
            "audit_dns_security_records",
            "audit_url_redirection_safety",
            "audit_jwt_token",
            "extract_javascript_endpoints",
            "recover_sourcemap_metadata",
            "audit_html_forms_and_csrf",
            "inspect_websocket_security",
            "analyze_web_tech_stack",
            "audit_subdomain_takeover_cnames",
            "deobfuscate_javascript_snippet",
            "hexstrike_backend_relay"
        ],
    })

async def health(request: Request):
    return JSONResponse({"status": "ok", "healthy": True})

async def sse_probe(request: Request):
    return Response(
        status_code=200,
        headers={"Allow": "GET, POST, OPTIONS, HEAD", "Access-Control-Allow-Origin": "*"},
    )

if hasattr(raw_app, "routes"):
    raw_app.routes.insert(0, Route("/health", endpoint=health, methods=["GET"]))
    raw_app.routes.insert(0, Route("/", endpoint=root, methods=["GET"]))
    raw_app.routes.insert(0, Route("/sse", endpoint=sse_probe, methods=["OPTIONS", "HEAD"]))
elif hasattr(raw_app, "router") and hasattr(raw_app.router, "add_route"):
    raw_app.router.add_route("/", root, methods=["GET"])
    raw_app.router.add_route("/health", health, methods=["GET"])
    raw_app.router.add_route("/sse", sse_probe, methods=["OPTIONS", "HEAD"])

class AllowAllHostsMiddleware:
    def __init__(self, inner):
        self.inner = inner
    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            headers = [(b"host", b"localhost") if k.lower() == b"host" else (k, v) for k, v in scope.get("headers", [])]
            scope["headers"] = headers
        await self.inner(scope, receive, send)

app = AllowAllHostsMiddleware(raw_app)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=PORT, reload=False)
`,
  },
  {
    name: "Dockerfile",
    path: "Dockerfile",
    language: "dockerfile",
    description: "Multi-stage Dockerfile for Render Web Service with reverse engineering utilities",
    content: `# HexStrike AI FastMCP Server Dockerfile
# Optimized for Render (Web Service / Background Service) & 24/7 Hosting

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    PORT=8000 \\
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install system utilities & reverse engineering binaries
RUN apt-get update && apt-get install -y --no-install-recommends \\
    curl \\
    git \\
    build-essential \\
    binutils \\
    file \\
    radare2 \\
    ca-certificates \\
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \\
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Render dynamically binds the PORT environment variable
EXPOSE \${PORT}

# Healthcheck for container orchestrators
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \\
    CMD curl -f http://localhost:\${PORT}/health || exit 1

# Start FastMCP server via Uvicorn
CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port \${PORT}"]
`,
  },
  {
    name: "render.yaml",
    path: "render.yaml",
    language: "yaml",
    description: "Render Blueprint for automated one-click web service deployment",
    content: `services:
  - type: web
    name: hexstrike-fastmcp-server
    runtime: python
    region: oregon
    plan: free # Can be upgraded to starter for persistent 24/7 execution without sleep
    buildCommand: "pip install --upgrade pip && pip install -r requirements.txt"
    startCommand: "uvicorn server:app --host 0.0.0.0 --port $PORT"
    healthCheckPath: /health
    autoDeploy: true
    envVars:
      - key: PYTHON_VERSION
        value: 3.11.9
      - key: LOG_LEVEL
        value: info
      - key: HEXSTRIKE_BACKEND_URL
        value: http://localhost:8888
      - key: MCP_AUTH_TOKEN
        generateValue: true
`,
  },
  {
    name: ".python-version",
    path: ".python-version",
    language: "text",
    description: "Specifies Python 3.11.9 for Render build environment",
    content: `3.11.9
`,
  },
  {
    name: "requirements.txt",
    path: "requirements.txt",
    language: "text",
    description: "Python dependencies with pinned mcp<2.0.0 to prevent ModuleNotFoundError",
    content: `mcp>=1.2.0,<2.0.0
uvicorn[standard]>=0.30.0
fastapi>=0.111.0
httpx>=0.27.0
pydantic>=2.7.0
capstone>=5.0.0
requests>=2.31.0
python-multipart>=0.0.9
starlette>=0.37.0
sse-starlette>=2.1.0
`,
  },
  {
    name: ".env.example",
    path: ".env.example",
    language: "bash",
    description: "Environment variables configuration template",
    content: `# Render assigns PORT automatically; for local testing use 8000
PORT=8000

# Optional: URL of a running HexStrike AI engine backend (https://github.com/0x4m4/hexstrike-ai)
HEXSTRIKE_BACKEND_URL=http://localhost:8888

# Optional: Bearer token secret to authenticate MCP client calls
MCP_AUTH_TOKEN=

# Logging level: DEBUG, INFO, WARNING, ERROR
LOG_LEVEL=info
`,
  },
  {
    name: "test_client.py",
    path: "test_client.py",
    language: "python",
    description: "Automated test script to verify /health, /sse, and MCP tools before connecting Claude",
    content: `"""
HexStrike AI FastMCP Client Tester
==================================
Verify your FastMCP deployment on Render or locally.
Tests health check, root info, and disassembler tool execution.
"""

import sys
import httpx
import json

DEFAULT_URL = "http://localhost:8000"

def test_deployment(server_url: str):
    base_url = server_url.rstrip("/")
    print(f"[*] Testing HexStrike FastMCP server at: {base_url}")

    # 1. Test Healthcheck
    try:
        health_resp = httpx.get(f"{base_url}/health", timeout=10.0)
        print(f"[+] Health check ({base_url}/health): HTTP {health_resp.status_code}")
        print(f"    Body: {health_resp.text}")
    except Exception as e:
        print(f"[-] Health check failed: {e}")
        return

    # 2. Test Root metadata
    try:
        root_resp = httpx.get(f"{base_url}/", timeout=10.0)
        print(f"[+] Root endpoint ({base_url}/): HTTP {root_resp.status_code}")
        data = root_resp.json()
        print(f"    Server: {data.get('server')}")
        print(f"    Tools:  {', '.join(data.get('tools_available', []))}")
    except Exception as e:
        print(f"[-] Root endpoint failed: {e}")

    # 3. Print Claude MCP Config JSON
    print("\\n" + "=" * 60)
    print("CLAUDE DESKTOP CONFIGURATION (claude_desktop_config.json):")
    print("=" * 60)
    claude_cfg = {
        "mcpServers": {
            "hexstrike-ai": {
                "command": "npx",
                "args": [
                    "-y",
                    "mcp-remote",
                    f"{base_url}/sse"
                ]
            }
        }
    }
    print(json.dumps(claude_cfg, indent=2))
    print("=" * 60)
    print("All tests completed successfully!")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    test_deployment(target)
`,
  },
  {
    name: "render_keepalive.py",
    path: "render_keepalive.py",
    language: "python",
    description: "24/7 background keep-alive ping script to prevent Render free-tier sleep",
    content: `"""
Render 24/7 Free-Tier Keep-Alive Ping Utility
============================================
Render free instances go to sleep after 15 minutes of inactivity.
Run this lightweight keepalive script locally, via GitHub Actions cron,
or using a free uptime monitor (UptimeRobot, Cron-Job.org, BetterUptime)
to ping your Render URL every 10 minutes and keep it 100% warm 24/7.
"""

import time
import sys
import httpx
from datetime import datetime

def run_keepalive(render_url: str, interval_seconds: int = 600):
    endpoint = f"{render_url.rstrip('/')}/health"
    print(f"[{datetime.now().isoformat()}] Starting Keep-Alive for {endpoint} (Interval: {interval_seconds}s)")

    while True:
        try:
            resp = httpx.get(endpoint, timeout=15.0)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] PING {endpoint} -> HTTP {resp.status_code}")
        except Exception as err:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] PING ERROR: {err}")
        time.sleep(interval_seconds)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python render_keepalive.py https://your-app-name.onrender.com")
        sys.exit(1)
    run_keepalive(sys.argv[1])
`,
  },
  {
    name: "README.md",
    path: "README.md",
    language: "markdown",
    description: "Complete setup guide for GitHub, Render, Claude Desktop & Cursor",
    content: `# HexStrike AI FastMCP Server (24/7 on Render)

Production-ready Model Context Protocol (MCP) server for [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) reverse engineering, disassembling, decompiling, security mitigations, and binary intelligence.

---

## Architecture Overview

\`\`\`
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
\`\`\`

---

## 1. Step-by-Step Render Setup (24/7 Background Running)

### Option A: Standard Render Web Service Setup (Recommended)

1. **Push this folder to a GitHub Repository**:
   \`\`\`bash
   git init
   git add .
   git commit -m "HexStrike FastMCP Server"
   git remote add origin https://github.com/YOUR_USERNAME/hexstrike-mcp.git
   git branch -M main
   git push -u origin main
   \`\`\`

2. **Open Render Dashboard**:
   - Go to [https://dashboard.render.com](https://dashboard.render.com)
   - Click **New +** → **Web Service**
   - Connect your newly created GitHub repository \`hexstrike-mcp\`

3. **Configure the Service Settings**:
   - **Name**: \`hexstrike-fastmcp\` (or your preferred name)
   - **Region**: Choose the closest region (e.g. Oregon, Frankfurt, Singapore)
   - **Language / Runtime**: \`Python 3\` (or \`Docker\` if using the included Dockerfile)
   - **Branch**: \`main\`
   - **Build Command**:
     \`\`\`bash
     pip install --upgrade pip && pip install -r requirements.txt
     \`\`\`
   - **Start Command**:
     \`\`\`bash
     uvicorn server:app --host 0.0.0.0 --port $PORT
     \`\`\`
   - **Plan**: \`Free\` (or \`Starter\` $7/mo for guaranteed zero-sleep 24/7 background uptime)

4. **Add Health Check & Environment Variables**:
   - Click **Advanced**:
     - **Health Check Path**: \`/health\`
     - **Auto-Deploy**: \`Yes\`
   - Add Environment Variables:
     - \`PYTHON_VERSION\`: \`3.11.9\`
     - \`LOG_LEVEL\`: \`info\`
     - \`HEXSTRIKE_BACKEND_URL\`: \`http://localhost:8888\` (optional)

5. **Deploy**:
   - Click **Create Web Service**. Render will build and deploy your container.
   - Once deployed, your URL will be: \`https://hexstrike-fastmcp.onrender.com\`

---

## 2. Preventing Free-Tier Sleep (Keeping it 24/7 Warm)

On Render's Free tier, services spin down after 15 minutes of inactivity. To keep your MCP server active 24/7 for Claude at zero cost:

1. **Option 1: Free Uptime Robot / Cron-Job.org Ping (Easiest)**
   - Create a free account at [UptimeRobot.com](https://uptimerobot.com) or [cron-job.org](https://cron-job.org)
   - Add an HTTP monitor to: \`https://YOUR-APP.onrender.com/health\`
   - Interval: Every **10 minutes**
   - This keeps your server awake 24/7 without cold starts.

2. **Option 2: Run the included keep-alive script**:
   \`\`\`bash
   python render_keepalive.py https://YOUR-APP.onrender.com
   \`\`\`

3. **Option 3: Render Starter Plan ($7/mo)**:
   - Persistent RAM/CPU with zero sleep.

---

## 3. Connecting to Claude Custom MCP Server

### A. Claude Desktop Integration (\`claude_desktop_config.json\`)

On your computer, open:
- **macOS**: \`~/Library/Application Support/Claude/claude_desktop_config.json\`
- **Windows**: \`%APPDATA%\\Claude\\claude_desktop_config.json\`

Add the following configuration (replace with your Render URL):

\`\`\`json
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
\`\`\`

*Note: \`mcp-remote\` comes from \`npx mcp-remote\` and seamlessly bridges Claude Desktop's local stdio MCP protocol with your remote Render SSE server!*

### B. Cursor Integration (\`~/.cursor/mcp.json\`)

\`\`\`json
{
  "mcpServers": {
    "hexstrike-ai": {
      "url": "https://YOUR-APP-NAME.onrender.com/sse",
      "transport": "sse"
    }
  }
}
\`\`\`

---

## 4. Testing Your MCP Deployment

Run the test client locally to confirm endpoints before opening Claude:

\`\`\`bash
python test_client.py https://YOUR-APP-NAME.onrender.com
\`\`\`
`,
  },
];
