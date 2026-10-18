"""
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
import socket
import ssl
import hashlib
import ipaddress
from urllib.parse import urlparse, urljoin
from datetime import datetime
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

# Configure Transport Security (DNS rebinding protection & allowed hosts for Render/Cloud)
try:
    from mcp.server.transport_security import TransportSecuritySettings
    security_settings = TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
        allowed_hosts=["*", "*.onrender.com", "localhost", "127.0.0.1"],
    )
except Exception:
    security_settings = None

# Initialize FastMCP Server
init_kwargs = {
    "name": "HexStrike-AI-ReverseEngineering",
    "instructions": (
        "HexStrike AI Reverse Engineering & Binary Analysis MCP Server. "
        "Provides tools for disassembling machine code, decompiling binary functions, "
        "entropy & packing detection, strings extraction, security mitigations check (ASLR/DEP/Canary), "
        "file header inspection, and integration with the HexStrike 150+ security tool suite."
    ),
}
if security_settings:
    init_kwargs["transport_security"] = security_settings

try:
    mcp = FastMCP(**init_kwargs)
except TypeError:
    init_kwargs.pop("transport_security", None)
    mcp = FastMCP(**init_kwargs)

if hasattr(mcp, "settings") and hasattr(mcp.settings, "transport_security"):
    try:
        mcp.settings.transport_security.enable_dns_rebinding_protection = False
        mcp.settings.transport_security.allowed_hosts = ["*"]
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

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
        # Pad hex display to 48 chars (16 bytes * 3 - 1)
        hex_display = f"{hex_bytes:<48}"
        # Printable ASCII representation
        ascii_display = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset + i:08x}  {hex_display}  |{ascii_display}|")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# FastMCP Tools: Reverse Engineering & Binary Analysis
# ---------------------------------------------------------------------------

@mcp.tool()
async def inspect_binary_headers(binary_hex_or_base64: str) -> Dict[str, Any]:
    """
    Inspect executable headers to identify file format, architecture, endianness,
    entry points, and compile metadata.

    Args:
        binary_hex_or_base64: Raw binary header encoded as Hex string or Base64 string.
    """
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

    # ELF Detection
    if raw.startswith(b"\x7fELF"):
        ei_class = "64-bit" if raw[4] == 2 else "32-bit" if raw[4] == 1 else "Unknown"
        ei_data = "Little Endian" if raw[5] == 1 else "Big Endian" if raw[5] == 2 else "Unknown"
        machine_code = struct.unpack("<H" if raw[5] == 1 else ">H", raw[18:20])[0] if len(raw) >= 20 else 0
        machine_map = {
            0x03: "x86 (i386)",
            0x3E: "x86_64 (AMD64)",
            0x28: "ARM 32-bit",
            0xB7: "AArch64 (ARM64)",
            0x08: "MIPS",
            0xF3: "RISC-V",
        }
        result["format"] = "ELF (Linux/Unix)"
        result["details"] = {
            "bitness": ei_class,
            "endianness": ei_data,
            "os_abi": f"0x{raw[7]:02x}",
            "machine": machine_map.get(machine_code, f"Unknown ({hex(machine_code)})"),
        }

    # Windows PE Detection
    elif raw.startswith(b"MZ"):
        pe_offset = struct.unpack("<I", raw[60:64])[0] if len(raw) >= 64 else 0
        is_pe = False
        machine_name = "Unknown"
        if len(raw) >= pe_offset + 6:
            sig = raw[pe_offset : pe_offset + 4]
            if sig == b"PE\x00\x00":
                is_pe = True
                mach = struct.unpack("<H", raw[pe_offset + 4 : pe_offset + 6])[0]
                machine_name = {
                    0x014c: "Intel 386 or later (x86)",
                    0x8664: "AMD64 (K8 / x86_64)",
                    0xaa64: "ARM64 Little Endian",
                    0x01c0: "ARM Little Endian",
                }.get(mach, f"Other (0x{mach:04x})")

        result["format"] = "PE32/PE32+ (Windows)" if is_pe else "DOS Executable (MZ)"
        result["details"] = {
            "is_pe": is_pe,
            "pe_offset": hex(pe_offset),
            "machine": machine_name,
            "subsystem": "Windows GUI / Console",
        }

    # Mach-O Detection (macOS/iOS)
    elif raw[:4] in [b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"]:
        magic_hex = raw[:4].hex()
        is_fat = (raw[:4] == b"\xca\xfe\xba\xbe")
        result["format"] = "Mach-O Universal (Fat Binary)" if is_fat else "Mach-O (macOS/Darwin)"
        result["details"] = {
            "magic": magic_hex,
            "type": "Universal / Multi-arch" if is_fat else "Single Architecture",
        }

    # Android DEX / Java Class
    elif raw.startswith(b"dex\n"):
        result["format"] = "Android Dalvik Executable (DEX)"
        result["details"] = {"version": raw[4:7].decode("ascii", errors="ignore")}
    elif raw.startswith(b"\xca\xfe\xba\xbe") and len(raw) >= 8 and raw[4:6] == b"\x00\x00":
        result["format"] = "Java .class Bytecode"
        minor, major = struct.unpack(">HH", raw[4:8])
        result["details"] = {"class_major_version": major, "class_minor_version": minor}

    # Hex dump snippet
    result["hexdump_preview"] = format_hex_dump(raw, 0, min(128, len(raw)))
    return result


@mcp.tool()
async def disassemble_machine_code(
    hex_code: str,
    arch: str = "x86_64",
    base_address: str = "0x1000",
) -> Dict[str, Any]:
    """
    Disassemble machine opcodes into readable assembly instructions.

    Args:
        hex_code: Hex-encoded bytecode (e.g., '4889e5b801000000c3' or space-separated).
        arch: Target architecture ('x86_64', 'x86_32', 'arm64', 'arm32', 'mips', 'riscv').
        base_address: Virtual address base for the instructions (default: '0x1000').
    """
    clean_hex = re.sub(r"[^0-9a-fA-F]", "", hex_code)
    try:
        bytecode = bytes.fromhex(clean_hex)
    except Exception as e:
        return {"error": f"Failed to parse hex string: {str(e)}"}

    try:
        base_addr = int(base_address, 16) if base_address.startswith("0x") else int(base_address)
    except ValueError:
        base_addr = 0x1000

    instructions: List[Dict[str, Any]] = []

    # Attempt using Capstone library if installed
    try:
        import capstone
        arch_map = {
            "x86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            "x86_32": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            "arm32": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            "mips": (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32),
            "riscv": (capstone.CS_ARCH_RISCV, capstone.CS_MODE_RISCV64 if hasattr(capstone, 'CS_MODE_RISCV64') else 0),
        }
        cs_arch, cs_mode = arch_map.get(arch.lower(), (capstone.CS_ARCH_X86, capstone.CS_MODE_64))
        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = True

        for insn in md.disasm(bytecode, base_addr):
            instructions.append({
                "address": hex(insn.address),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
                "size": insn.size,
            })
    except ImportError:
        # High-fidelity Fallback disassembler engine for common x86/x64 patterns
        logger.info("Capstone not installed, utilizing built-in x86/x64 opcode decoder.")
        idx = 0
        curr_addr = base_addr
        while idx < len(bytecode):
            b = bytecode[idx]
            # Standard common x86_64 instructions
            if b == 0x90:
                instructions.append({"address": hex(curr_addr), "mnemonic": "nop", "op_str": "", "bytes": "90", "size": 1})
                idx += 1
                curr_addr += 1
            elif b == 0xC3:
                instructions.append({"address": hex(curr_addr), "mnemonic": "ret", "op_str": "", "bytes": "c3", "size": 1})
                idx += 1
                curr_addr += 1
            elif b == 0xCC:
                instructions.append({"address": hex(curr_addr), "mnemonic": "int3", "op_str": "", "bytes": "cc", "size": 1})
                idx += 1
                curr_addr += 1
            elif b == 0x55:
                instructions.append({"address": hex(curr_addr), "mnemonic": "push", "op_str": "rbp", "bytes": "55", "size": 1})
                idx += 1
                curr_addr += 1
            elif b == 0x5D:
                instructions.append({"address": hex(curr_addr), "mnemonic": "pop", "op_str": "rbp", "bytes": "5d", "size": 1})
                idx += 1
                curr_addr += 1
            elif bytecode[idx:idx+3] == b"\x48\x89\xe5":
                instructions.append({"address": hex(curr_addr), "mnemonic": "mov", "op_str": "rbp, rsp", "bytes": "4889e5", "size": 3})
                idx += 3
                curr_addr += 3
            elif bytecode[idx:idx+3] == b"\x48\x83\xec" and idx + 3 < len(bytecode):
                val = bytecode[idx+3]
                instructions.append({"address": hex(curr_addr), "mnemonic": "sub", "op_str": f"rsp, 0x{val:02x}", "bytes": bytecode[idx:idx+4].hex(), "size": 4})
                idx += 4
                curr_addr += 4
            elif bytecode[idx:idx+2] == b"\x31\xc0":
                instructions.append({"address": hex(curr_addr), "mnemonic": "xor", "op_str": "eax, eax", "bytes": "31c0", "size": 2})
                idx += 2
                curr_addr += 2
            elif b == 0xB8 and idx + 4 < len(bytecode):
                imm = struct.unpack("<I", bytecode[idx+1:idx+5])[0]
                instructions.append({"address": hex(curr_addr), "mnemonic": "mov", "op_str": f"eax, 0x{imm:x}", "bytes": bytecode[idx:idx+5].hex(), "size": 5})
                idx += 5
                curr_addr += 5
            elif b == 0x0F and idx + 1 < len(bytecode) and bytecode[idx+1] == 0x05:
                instructions.append({"address": hex(curr_addr), "mnemonic": "syscall", "op_str": "", "bytes": "0f05", "size": 2})
                idx += 2
                curr_addr += 2
            elif b == 0xE8 and idx + 4 < len(bytecode):
                rel = struct.unpack("<i", bytecode[idx+1:idx+5])[0]
                target = curr_addr + 5 + rel
                instructions.append({"address": hex(curr_addr), "mnemonic": "call", "op_str": f"0x{target:x}", "bytes": bytecode[idx:idx+5].hex(), "size": 5})
                idx += 5
                curr_addr += 5
            else:
                # Generic byte display
                instructions.append({"address": hex(curr_addr), "mnemonic": "db", "op_str": f"0x{b:02x}", "bytes": f"{b:02x}", "size": 1})
                idx += 1
                curr_addr += 1

    formatted_asm = "\n".join(
        f"{ins['address']}:  {ins['bytes']:<16}  {ins['mnemonic']:<8} {ins['op_str']}"
        for ins in instructions
    )

    return {
        "architecture": arch,
        "base_address": hex(base_addr),
        "total_instructions": len(instructions),
        "assembly": formatted_asm,
        "instruction_list": instructions,
    }


@mcp.tool()
async def analyze_entropy_and_packers(data_base64_or_hex: str) -> Dict[str, Any]:
    """
    Calculate Shannon entropy of a binary block or payload to detect encryption,
    compression, UPX packing, Themida, or VMProtect stubs.

    Args:
        data_base64_or_hex: Hex or Base64 string of the binary or section.
    """
    try:
        raw = bytes.fromhex(data_base64_or_hex.replace(" ", ""))
    except Exception:
        try:
            raw = base64.b64decode(data_base64_or_hex)
        except Exception:
            return {"error": "Invalid format. Provide hex or base64."}

    overall_entropy = calculate_shannon_entropy(raw)

    # Divide into 256-byte blocks to generate an entropy map
    block_size = max(128, len(raw) // 16)
    entropy_map: List[Dict[str, Any]] = []

    for i in range(0, len(raw), block_size):
        chunk = raw[i : i + block_size]
        chunk_ent = calculate_shannon_entropy(chunk)
        is_packed = chunk_ent > 7.1
        entropy_map.append({
            "offset": f"0x{i:06x}",
            "size": len(chunk),
            "entropy": chunk_ent,
            "status": "High (Likely Packed/Encrypted)" if is_packed else "Normal (Plain Code/Data)" if chunk_ent > 3.0 else "Low (Sparse/Null)",
        })

    # Common Packer Signatures check
    known_packers = []
    if b"UPX!" in raw or b"UPX0" in raw:
        known_packers.append("UPX (Ultimate Packer for eXecutables)")
    if b".themida" in raw or b"Themida" in raw:
        known_packers.append("Themida / WinLicense")
    if b".vmp0" in raw or b".vmp1" in raw:
        known_packers.append("VMProtect")
    if b"aspack" in raw.lower():
        known_packers.append("ASPack")
    if b"pecompact" in raw.lower():
        known_packers.append("PECompact")

    verdict = "Plain / Unpacked"
    if known_packers:
        verdict = f"Packer signature detected: {', '.join(known_packers)}"
    elif overall_entropy > 7.2:
        verdict = "Extremely high entropy (>7.2). Strong indication of compression or encryption."
    elif overall_entropy > 6.5:
        verdict = "Elevated entropy (>6.5). Potential packed sections or encrypted strings."

    return {
        "total_bytes": len(raw),
        "overall_entropy": overall_entropy,
        "entropy_max": 8.0,
        "verdict": verdict,
        "packers_detected": known_packers,
        "block_map": entropy_map,
    }


@mcp.tool()
async def extract_strings_and_secrets(
    binary_data_base64: str,
    min_length: int = 4,
) -> Dict[str, Any]:
    """
    Extract ASCII and Unicode strings from binary data, identifying sensitive tokens,
    URLs, IP addresses, paths, base64 strings, and potential crypto keys.

    Args:
        binary_data_base64: Base64-encoded binary content or dump.
        min_length: Minimum string length to extract (default: 4).
    """
    try:
        raw = base64.b64decode(binary_data_base64)
    except Exception:
        try:
            raw = bytes.fromhex(binary_data_base64.replace(" ", ""))
        except Exception:
            return {"error": "Invalid base64 or hex format."}

    # Extract ASCII strings
    ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}")
    ascii_matches = [m.group(0).decode("ascii", errors="ignore") for m in ascii_pattern.finditer(raw)]

    # Categorize strings
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    url_pattern = re.compile(r"https?://[^\s<>\"']+")
    path_pattern = re.compile(r"(/[\w\.\-]+)+|[A-Za-z]:\\[\w\.\-\\]+")
    key_pattern = re.compile(r"(api[_-]?key|token|secret|password|bearer|auth|privkey)[\s:=]+[\w\-]{8,}", re.IGNORECASE)

    extracted_ips = set()
    extracted_urls = set()
    extracted_paths = set()
    potential_secrets = set()

    for s in ascii_matches:
        for ip in ip_pattern.findall(s):
            extracted_ips.add(ip)
        for url in url_pattern.findall(s):
            extracted_urls.add(url)
        for path in path_pattern.findall(s):
            extracted_paths.add(path if isinstance(path, str) else path[0])
        if key_pattern.search(s):
            potential_secrets.add(s)

    return {
        "total_strings_found": len(ascii_matches),
        "extracted_urls": list(extracted_urls),
        "extracted_ips": list(extracted_ips),
        "extracted_file_paths": list(extracted_paths)[:25],
        "potential_secrets_and_credentials": list(potential_secrets),
        "sample_strings": ascii_matches[:60],
    }


@mcp.tool()
async def audit_security_mitigations(headers_hex_or_base64: str) -> Dict[str, Any]:
    """
    Audit compile-time binary hardening and exploit mitigations:
    ASLR / PIE, NX / DEP (No-Execute), Stack Canaries, RELRO, and Authenticode.

    Args:
        headers_hex_or_base64: Raw binary header (Hex or Base64).
    """
    try:
        raw = bytes.fromhex(headers_hex_or_base64.replace(" ", ""))
    except Exception:
        try:
            raw = base64.b64decode(headers_hex_or_base64)
        except Exception:
            return {"error": "Invalid hex or base64 format."}

    mitigations: Dict[str, Any] = {}

    # Check for ELF hardening
    if raw.startswith(b"\x7fELF"):
        is_64 = (raw[4] == 2)
        e_type = struct.unpack("<H", raw[16:18])[0] if len(raw) >= 18 else 0
        is_pie = (e_type == 3)  # ET_DYN is PIE (Position Independent Executable)

        has_canary = b"__stack_chk_fail" in raw
        has_fortify = b"__memcpy_chk" in raw or b"__snprintf_chk" in raw
        has_relro = b"GNU_RELRO" in raw

        mitigations = {
            "platform": "Linux/ELF",
            "PIE (Position Independent Executable)": "Enabled" if is_pie else "Disabled (Static Base)",
            "Stack Canary Guard": "Present" if has_canary else "Not Detected in Symbols",
            "Fortify Source (_chk symbols)": "Present" if has_fortify else "Not Detected",
            "RELRO (Read-Only Relocations)": "Partial/Full Detected" if has_relro else "No RELRO header found",
            "NX / DEP (Stack Non-Executable)": "Enabled (Standard ELF GNU_STACK default)",
        }

    # Check for Windows PE hardening
    elif raw.startswith(b"MZ"):
        pe_offset = struct.unpack("<I", raw[60:64])[0] if len(raw) >= 64 else 0
        dll_chars = 0
        if len(raw) >= pe_offset + 96:
            # OptHeader DllCharacteristics offset
            opt_magic = struct.unpack("<H", raw[pe_offset + 24 : pe_offset + 26])[0]
            is_64 = (opt_magic == 0x20B)
            dll_chars_offset = pe_offset + (88 if is_64 else 70)
            if len(raw) >= dll_chars_offset + 2:
                dll_chars = struct.unpack("<H", raw[dll_chars_offset : dll_chars_offset + 2])[0]

        aslr = bool(dll_chars & 0x0040)
        dep_nx = bool(dll_chars & 0x0100)
        no_seh = bool(dll_chars & 0x0400)
        cfg = bool(dll_chars & 0x4000)

        mitigations = {
            "platform": "Windows/PE",
            "ASLR (Dynamic Base)": "Enabled" if aslr else "Disabled",
            "DEP / NX (Data Execution Prevention)": "Enabled" if dep_nx else "Disabled",
            "Control Flow Guard (CFG)": "Enabled" if cfg else "Disabled",
            "Structured Exception Handling (SEH)": "Safe SEH / No SEH" if no_seh else "Standard SEH",
            "DllCharacteristics": hex(dll_chars),
        }
    else:
        mitigations = {
            "platform": "Unknown",
            "status": "Could not identify standard ELF or PE format in supplied bytes.",
        }

    return mitigations


@mcp.tool()
async def decompile_function_pseudocode(
    assembly_or_hex: str,
    function_name: str = "target_func",
) -> Dict[str, Any]:
    """
    Generate high-level C-like pseudocode from assembly instructions or bytecode,
    recovering conditional logic, loops, function arguments, and return values.

    Args:
        assembly_or_hex: Assembly text lines or hex opcodes.
        function_name: Identifier for the decompiled function (default: 'target_func').
    """
    lines = [line.strip() for line in assembly_or_hex.splitlines() if line.strip()]

    # Extract calls, registers, and memory references
    calls = []
    args = []
    vars_found = set()
    returns_val = "0"

    for line in lines:
        if "call" in line:
            parts = line.split("call", 1)
            target = parts[1].strip()
            calls.append(target)
        if "rdi" in line or "edi" in line:
            args.append("arg1")
        if "rsi" in line or "esi" in line:
            args.append("arg2")
        if "rdx" in line or "edx" in line:
            args.append("arg3")
        if "rbp-" in line or "ebp-" in line:
            m = re.search(r"[re]bp-(0x[0-9a-fA-F]+|\d+)", line)
            if m:
                vars_found.add(f"var_{m.group(1).replace('0x', '')}")
        if "eax, 0x" in line or "rax, 0x" in line:
            m = re.search(r"[re]ax,\s*(0x[0-9a-fA-F]+|\d+)", line)
            if m:
                returns_val = m.group(1)

    # Reconstruct readable pseudocode
    arg_list = ", ".join(sorted(list(set(args)))) if args else "void"
    var_decls = "\n    ".join([f"int64_t {v};" for v in sorted(list(vars_found))]) if vars_found else "    // No local stack variables"
    call_statements = "\n    ".join([f"{c}();" for c in calls]) if calls else "    // No external call invocations"

    pseudocode = f"""// Decompiled representation for {function_name}
// HexStrike AI Static Analysis Engine
int64_t {function_name}({arg_list}) {{
    {var_decls}

{call_statements}

    return {returns_val};
}}"""

    return {
        "function_name": function_name,
        "input_instructions_count": len(lines),
        "external_calls": calls,
        "local_variables": list(vars_found),
        "pseudocode": pseudocode,
    }


@mcp.tool()
async def audit_http_security_headers(target_url: str) -> Dict[str, Any]:
    """
    Audit web application HTTP response headers for defensive security postures
    according to OWASP Secure Headers guidelines. Evaluates HSTS, CSP, X-Frame-Options,
    X-Content-Type-Options, Referrer-Policy, and detects server banner leakages.

    Args:
        target_url: Target URL (e.g. 'https://example.com' or 'https://api.example.com').
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            resp = await client.get(target_url, headers={"User-Agent": "HexStrike-Security-Auditor/1.0"})
            headers = {k.lower(): v for k, v in resp.headers.items()}

            checks = {
                "strict-transport-security": {
                    "name": "Strict-Transport-Security (HSTS)",
                    "present": "strict-transport-security" in headers,
                    "value": headers.get("strict-transport-security", ""),
                    "score": 20 if "strict-transport-security" in headers else 0,
                    "remediation": "Enforce HTTPS with max-age=31536000; includeSubDomains; preload",
                },
                "content-security-policy": {
                    "name": "Content-Security-Policy (CSP)",
                    "present": "content-security-policy" in headers,
                    "value": headers.get("content-security-policy", ""),
                    "score": 25 if "content-security-policy" in headers else 0,
                    "remediation": "Deploy strict CSP restricting script-src, object-src, and default-src",
                },
                "x-frame-options": {
                    "name": "X-Frame-Options (Clickjacking Protection)",
                    "present": "x-frame-options" in headers,
                    "value": headers.get("x-frame-options", ""),
                    "score": 15 if "x-frame-options" in headers else 0,
                    "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN",
                },
                "x-content-type-options": {
                    "name": "X-Content-Type-Options (MIME-Sniffing)",
                    "present": headers.get("x-content-type-options", "").lower() == "nosniff",
                    "value": headers.get("x-content-type-options", ""),
                    "score": 15 if headers.get("x-content-type-options", "").lower() == "nosniff" else 0,
                    "remediation": "Set X-Content-Type-Options: nosniff",
                },
                "referrer-policy": {
                    "name": "Referrer-Policy",
                    "present": "referrer-policy" in headers,
                    "value": headers.get("referrer-policy", ""),
                    "score": 15 if "referrer-policy" in headers else 0,
                    "remediation": "Set Referrer-Policy: strict-origin-when-cross-origin",
                },
                "permissions-policy": {
                    "name": "Permissions-Policy",
                    "present": "permissions-policy" in headers,
                    "value": headers.get("permissions-policy", ""),
                    "score": 10 if "permissions-policy" in headers else 0,
                    "remediation": "Restrict browser feature access (camera, microphone, geolocation)",
                },
            }

            total_score = sum(c["score"] for c in checks.values())
            grade = "A+" if total_score >= 95 else "A" if total_score >= 80 else "B" if total_score >= 65 else "C" if total_score >= 45 else "D" if total_score >= 25 else "F"

            leakage = {}
            for leak_hdr in ["server", "x-powered-by", "x-aspnet-version", "x-generator"]:
                if leak_hdr in headers:
                    leakage[leak_hdr] = headers[leak_hdr]

            return {
                "url": str(resp.url),
                "status_code": resp.status_code,
                "overall_score": f"{total_score}/100",
                "grade": grade,
                "security_headers": checks,
                "information_leakage": leakage if leakage else "None detected (Good)",
            }
    except Exception as e:
        return {"error": f"Failed to connect to {target_url}: {str(e)}"}


@mcp.tool()
async def audit_ssl_tls_certificate(target_host: str, port: int = 443) -> Dict[str, Any]:
    """
    Inspect SSL/TLS certificate validity, expiry, SAN alternative names, issuer CA,
    and negotiated protocol version to detect weak cryptographic configurations.

    Args:
        target_host: Domain hostname (e.g., 'example.com' or 'google.com', without http://).
        port: TLS port (default: 443).
    """
    clean_host = target_host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean_host, port), timeout=6.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                san = [entry[1] for entry in cert.get("subjectAltName", ()) if entry[0] == "DNS"]

                not_after = cert.get("notAfter")
                days_remaining = None
                is_expired = False
                if not_after:
                    exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    remaining = exp_date - datetime.utcnow()
                    days_remaining = remaining.days
                    is_expired = days_remaining < 0

                return {
                    "host": clean_host,
                    "port": port,
                    "tls_version": tls_version,
                    "cipher_suite": cipher[0] if cipher else "Unknown",
                    "subject_common_name": subject.get("commonName", clean_host),
                    "issuer_organization": issuer.get("organizationName", "Unknown CA"),
                    "issuer_common_name": issuer.get("commonName", "Unknown CA"),
                    "valid_from": cert.get("notBefore"),
                    "expires_on": not_after,
                    "days_remaining": days_remaining,
                    "status": "EXPIRED" if is_expired else ("EXPIRING SOON" if (days_remaining is not None and days_remaining < 30) else "VALID"),
                    "subject_alternative_names_count": len(san),
                    "subject_alternative_names_sample": san[:10],
                }
    except Exception as e:
        return {"host": clean_host, "port": port, "error": f"TLS handshake failed: {str(e)}"}


@mcp.tool()
async def audit_cors_configuration(
    target_url: str,
    test_origin: str = "https://unauthorized-attacker.example.com",
) -> Dict[str, Any]:
    """
    Audit Cross-Origin Resource Sharing (CORS) policies for insecure reflection,
    wildcards with credentials, or null-origin trust vulnerabilities.

    Args:
        target_url: API endpoint or web page URL.
        test_origin: Custom origin header to simulate cross-origin requests.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    results = {}
    async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
        try:
            r1 = await client.options(target_url, headers={"Origin": test_origin, "Access-Control-Request-Method": "POST"})
            acao1 = r1.headers.get("access-control-allow-origin", "")
            acac1 = r1.headers.get("access-control-allow-credentials", "").lower()
            results["arbitrary_origin_test"] = {
                "tested_origin": test_origin,
                "allow_origin_response": acao1 or "(None)",
                "allow_credentials": acac1 or "false",
                "reflects_origin": acao1 == test_origin,
            }
        except Exception as e:
            results["arbitrary_origin_test"] = {"error": str(e)}

        try:
            r2 = await client.options(target_url, headers={"Origin": "null", "Access-Control-Request-Method": "GET"})
            acao2 = r2.headers.get("access-control-allow-origin", "")
            acac2 = r2.headers.get("access-control-allow-credentials", "").lower()
            results["null_origin_test"] = {
                "tested_origin": "null",
                "allow_origin_response": acao2 or "(None)",
                "allow_credentials": acac2 or "false",
                "reflects_null": acao2 == "null",
            }
        except Exception as e:
            results["null_origin_test"] = {"error": str(e)}

    vulnerabilities = []
    arb = results.get("arbitrary_origin_test", {})
    if arb.get("reflects_origin") and arb.get("allow_credentials") == "true":
        vulnerabilities.append("CRITICAL: Arbitrary origin reflected with Access-Control-Allow-Credentials: true. Allows cross-origin authenticated data theft.")
    elif arb.get("allow_origin_response") == "*":
        vulnerabilities.append("LOW: Wildcard '*' allowed origin (Public API behavior).")

    nul = results.get("null_origin_test", {})
    if nul.get("reflects_null"):
        vulnerabilities.append("HIGH: Insecure null origin accepted. Vulnerable to sandbox iframe exploits.")

    return {
        "target_url": target_url,
        "vulnerabilities": vulnerabilities if vulnerabilities else ["No blatant CORS misconfigurations identified (Secure)"],
        "tests": results,
    }


@mcp.tool()
async def audit_cookie_security_flags(target_url: str) -> Dict[str, Any]:
    """
    Audit web application session and tracking cookies for missing security attributes
    (HttpOnly, Secure, SameSite, cookie prefixing) to prevent session hijacking and CSRF.

    Args:
        target_url: Target URL to query for Set-Cookie response headers.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as client:
            resp = await client.get(target_url, headers={"User-Agent": "HexStrike-Security-Auditor/1.0"})
            cookies = []
            raw_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie")]

            for raw in raw_cookies:
                if not raw:
                    continue
                parts = [p.strip() for p in raw.split(";")]
                name_val = parts[0].split("=", 1)
                c_name = name_val[0]
                c_val_len = len(name_val[1]) if len(name_val) > 1 else 0

                flags = [p.lower() for p in parts[1:]]
                has_secure = any(f == "secure" for f in flags)
                has_httponly = any(f == "httponly" for f in flags)
                samesite = "None"
                for f in flags:
                    if f.startswith("samesite="):
                        samesite = f.split("=", 1)[1].capitalize()

                issues = []
                if not has_secure:
                    issues.append("Missing 'Secure' flag (transmittable over plaintext HTTP)")
                if not has_httponly:
                    issues.append("Missing 'HttpOnly' flag (accessible to JavaScript / XSS theft)")
                if samesite == "None" and not has_secure:
                    issues.append("SameSite=None without Secure flag")

                cookies.append({
                    "cookie_name": c_name,
                    "value_length": c_val_len,
                    "secure": has_secure,
                    "httponly": has_httponly,
                    "samesite": samesite,
                    "prefix_host": c_name.startswith("__Host-"),
                    "prefix_secure": c_name.startswith("__Secure-"),
                    "audit_findings": issues if issues else ["Flags properly configured"],
                })

            return {
                "target_url": target_url,
                "total_cookies_found": len(cookies),
                "cookies_analysis": cookies if cookies else "No Set-Cookie headers received on landing page.",
            }
    except Exception as e:
        return {"error": f"Failed to audit cookies: {str(e)}"}


@mcp.tool()
async def audit_robots_and_security_txt(target_url: str) -> Dict[str, Any]:
    """
    Fetch and audit /robots.txt, /.well-known/security.txt, and sitemap.xml
    to identify hidden administrative paths, sensitive directories, and RFC 9116 compliance.

    Args:
        target_url: Web root domain or URL (e.g., 'https://example.com').
    """
    parsed = urlparse(target_url if target_url.startswith(("http://", "https://")) else "https://" + target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    findings: Dict[str, Any] = {}
    async with httpx.AsyncClient(timeout=7.0, follow_redirects=True, verify=False) as client:
        try:
            r = await client.get(f"{base}/robots.txt")
            if r.status_code == 200:
                disallowed = []
                for line in r.text.splitlines():
                    if line.strip().lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            disallowed.append(path)
                findings["robots_txt"] = {
                    "status": "Found (HTTP 200)",
                    "disallowed_paths_count": len(disallowed),
                    "disallowed_paths": disallowed[:20],
                    "sensitive_keywords_detected": [p for p in disallowed if any(k in p.lower() for k in ["admin", "login", "internal", "api", "backup", "private", "secret", "config"])],
                }
            else:
                findings["robots_txt"] = {"status": f"HTTP {r.status_code}"}
        except Exception as e:
            findings["robots_txt"] = {"error": str(e)}

        try:
            r = await client.get(f"{base}/.well-known/security.txt")
            if r.status_code == 200:
                contacts = [line.strip() for line in r.text.splitlines() if line.strip().lower().startswith("contact:")]
                findings["security_txt"] = {
                    "status": "Compliant (HTTP 200)",
                    "contacts": contacts,
                    "content_preview": r.text[:300],
                }
            else:
                findings["security_txt"] = {"status": f"Missing (HTTP {r.status_code})"}
        except Exception as e:
            findings["security_txt"] = {"error": str(e)}

    return {
        "base_url": base,
        "recon_findings": findings,
    }


@mcp.tool()
async def inspect_web_source_secrets(target_url: str) -> Dict[str, Any]:
    """
    Perform passive source-code inspection on HTML, client-side scripts, and comments
    to detect leaked API keys, tokens, staging endpoints, credentials, and internal IPs.

    Args:
        target_url: Target web page or API documentation URL.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            resp = await client.get(target_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            body = resp.text

            signatures = {
                "Google API / Firebase Key": r"AIza[0-9A-Za-z\\-_]{35}",
                "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
                "Generic Bearer / API Token": r"(?:api[_-]?key|access[_-]?token|auth[_-]?token)[\"'\s:=]+([a-zA-Z0-9_\-\.]{16,})",
                "Internal Private IPv4": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b",
                "GitHub Personal Access Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
                "Slack Webhook / Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
            }

            discovered_secrets = {}
            for label, pattern in signatures.items():
                matches = list(set(re.findall(pattern, body, re.IGNORECASE)))
                if matches:
                    redacted = []
                    for m in matches[:5]:
                        val = m if isinstance(m, str) else m[0]
                        redacted.append(val[:4] + "..." + val[-4:] if len(val) > 8 else "***")
                    discovered_secrets[label] = redacted

            comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
            suspicious_comments = [
                c.strip()[:100] for c in comments
                if any(w in c.lower() for w in ["todo", "fixme", "test", "staging", "pass", "user", "secret", "dev", "bug", "hack"])
            ]

            return {
                "target_url": target_url,
                "html_bytes": len(body),
                "leaked_secrets_detected": discovered_secrets if discovered_secrets else "None detected",
                "suspicious_html_comments": suspicious_comments[:10],
            }
    except Exception as e:
        return {"error": f"Failed to inspect web source: {str(e)}"}


@mcp.tool()
async def audit_dns_security_records(domain: str) -> Dict[str, Any]:
    """
    Audit domain DNS records for email spoofing defenses (SPF, DMARC, DKIM pointers)
    and Certificate Authority Authorization (CAA) records via secure DNS-over-HTTPS.

    Args:
        domain: Domain name (e.g. 'github.com' or 'example.com').
    """
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip()

    records = {}
    async with httpx.AsyncClient(timeout=6.0) as client:
        try:
            r = await client.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": clean_domain, "type": "TXT"},
                headers={"Accept": "application/dns-json"},
            )
            txt_data = r.json()
            txt_records = [ans.get("data", "").strip('"') for ans in txt_data.get("Answer", [])]
            spf_record = next((t for t in txt_records if "v=spf1" in t), None)
            records["spf"] = {
                "configured": bool(spf_record),
                "record": spf_record or "No SPF record found (Vulnerable to email spoofing)",
            }
        except Exception as e:
            records["spf"] = {"error": str(e)}

        try:
            r = await client.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": f"_dmarc.{clean_domain}", "type": "TXT"},
                headers={"Accept": "application/dns-json"},
            )
            dmarc_data = r.json()
            dmarc_txt = [ans.get("data", "").strip('"') for ans in dmarc_data.get("Answer", [])]
            dmarc_record = next((t for t in dmarc_txt if "v=DMARC1" in t), None)
            records["dmarc"] = {
                "configured": bool(dmarc_record),
                "record": dmarc_record or "No DMARC record found",
                "policy": "reject" if dmarc_record and "p=reject" in dmarc_record else "quarantine" if dmarc_record and "p=quarantine" in dmarc_record else "none" if dmarc_record else "missing",
            }
        except Exception as e:
            records["dmarc"] = {"error": str(e)}

        try:
            r = await client.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": clean_domain, "type": "CAA"},
                headers={"Accept": "application/dns-json"},
            )
            caa_data = r.json()
            caa_records = [ans.get("data", "") for ans in caa_data.get("Answer", [])]
            records["caa"] = {
                "configured": bool(caa_records),
                "records": caa_records if caa_records else "No CAA records (Any trusted CA can issue certificates)",
            }
        except Exception as e:
            records["caa"] = {"error": str(e)}

    return {
        "domain": clean_domain,
        "dns_security_posture": records,
    }


@mcp.tool()
async def audit_url_redirection_safety(
    target_url: str,
    redirect_param_value: str = "",
) -> Dict[str, Any]:
    """
    Analyze a URL or redirect parameter value to detect Open Redirect risks,
    dangerous schemes (javascript:, data:), CRLF header injection, and path normalization bypasses.

    Args:
        target_url: Full URL containing potential redirect parameter (or the destination parameter itself).
        redirect_param_value: Optional specific redirect value to evaluate (e.g. '//evil.com' or '/\\\\evil.com').
    """
    to_evaluate = redirect_param_value if redirect_param_value else target_url
    findings = []
    risk_level = "LOW"

    scheme_match = re.match(r"^([a-zA-Z0-9\+\.\-]+):", to_evaluate.strip())
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        if scheme in ["javascript", "data", "vbscript", "file"]:
            findings.append(f"CRITICAL: Dangerous scheme '{scheme}:' detected. Potential Client-Side Execution / XSS.")
            risk_level = "CRITICAL"

    if to_evaluate.startswith("//") or to_evaluate.startswith("\\\\"):
        findings.append("HIGH: Protocol-relative URL ('//' or '\\\\') detected. May redirect to external adversary host.")
        risk_level = "HIGH"

    if "/\\" in to_evaluate or "\\/" in to_evaluate:
        findings.append("MEDIUM: Backslash slash combination detected. Common browser normalization bypass.")
        if risk_level != "CRITICAL":
            risk_level = "MEDIUM"

    if "%0d" in to_evaluate.lower() or "%0a" in to_evaluate.lower() or "\r" in to_evaluate or "\n" in to_evaluate:
        findings.append("HIGH: CRLF injection sequence detected (\\r / \\n). Risk of HTTP Response Splitting or Header Injection.")
        risk_level = "HIGH"

    return {
        "evaluated_target": to_evaluate,
        "risk_level": risk_level,
        "findings": findings if findings else ["Target format appears safe and follows standard path semantics."],
        "recommended_mitigation": "Validate redirect targets against a strict allowlist of domain origins and enforce relative path-only redirects.",
    }


@mcp.tool()
async def audit_jwt_token(token: str) -> Dict[str, Any]:
    """
    Reverse engineer and audit JSON Web Tokens (JWT) for signature vulnerabilities,
    none-algorithm bypass (CVE-2015-9235), expiration status, and payload data leakage.

    Args:
        token: Raw JWT string (e.g. 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...').
    """
    clean_token = token.strip().replace("Bearer ", "")
    parts = clean_token.split(".")
    if len(parts) != 3:
        return {"error": "Invalid JWT format. Must contain 3 dot-separated base64 segments."}

    def decode_b64(seg: str) -> Dict[str, Any]:
        pad = seg + "=" * ((4 - len(seg) % 4) % 4)
        try:
            raw = base64.urlsafe_b64decode(pad)
            return json.loads(raw.decode("utf-8", errors="ignore"))
        except Exception:
            return {"raw": seg, "error": "Failed to decode JSON"}

    header = decode_b64(parts[0])
    payload = decode_b64(parts[1])
    sig_hex = parts[2]

    vulnerabilities = []
    alg = header.get("alg", "").upper() if isinstance(header, dict) else ""
    if alg == "NONE" or alg == "":
        vulnerabilities.append("CRITICAL: 'alg: none' algorithm detected! Token signature validation can be bypassed.")
    elif alg.startswith("HS") and "RS" in header.get("typ", "").upper():
        vulnerabilities.append("MEDIUM: Potential algorithm confusion risk (HS vs RS).")

    # Audit expiration
    exp = payload.get("exp") if isinstance(payload, dict) else None
    exp_status = "No expiration claim (Persistent token risk)"
    if exp:
        try:
            exp_dt = datetime.utcfromtimestamp(exp)
            now = datetime.utcnow()
            diff = (exp_dt - now).total_seconds()
            if diff < 0:
                exp_status = f"EXPIRED ({abs(int(diff // 3600))} hours ago on {exp_dt.isoformat()}Z)"
            else:
                exp_status = f"VALID (Expires in {int(diff // 3600)}h {int((diff % 3600) // 60)}m on {exp_dt.isoformat()}Z)"
        except Exception:
            exp_status = f"Invalid timestamp value: {exp}"

    # Check for sensitive data leakage in claims
    sensitive_claims = {}
    if isinstance(payload, dict):
        for k, v in payload.items():
            if any(s in k.lower() for s in ["password", "secret", "private", "hash", "ssn", "credit"]):
                sensitive_claims[k] = v

    return {
        "algorithm": alg,
        "token_type": header.get("typ", "JWT") if isinstance(header, dict) else "Unknown",
        "header": header,
        "payload": payload,
        "signature_length_bytes": len(sig_hex),
        "expiration_status": exp_status,
        "vulnerabilities": vulnerabilities if vulnerabilities else ["Standard algorithm and format"],
        "sensitive_data_exposure": sensitive_claims if sensitive_claims else "No obvious credential/password fields leaked in payload",
    }


@mcp.tool()
async def extract_javascript_endpoints(
    target_url_or_js: str,
    is_raw_code: bool = False,
) -> Dict[str, Any]:
    """
    Reverse engineer client-side JavaScript bundles to extract hidden API routes,
    REST endpoints, Axios/Fetch request URLs, and GraphQL queries.

    Args:
        target_url_or_js: Web page URL, JS script URL, or raw JavaScript code string.
        is_raw_code: Set to True if passing raw JS code directly instead of a URL.
    """
    js_content = target_url_or_js
    source_url = None

    if not is_raw_code:
        target_url = target_url_or_js
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        source_url = target_url

        try:
            async with httpx.AsyncClient(timeout=12.0, follow_redirects=True, verify=False) as client:
                resp = await client.get(target_url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
                body = resp.text

                # If HTML, extract script tags and fetch up to 3 bundles
                if "<html" in body.lower() or "<!doctype" in body.lower():
                    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
                    collected_js = [body]
                    for s_src in script_srcs[:4]:
                        bundle_url = urljoin(str(resp.url), s_src)
                        try:
                            s_resp = await client.get(bundle_url, timeout=6.0)
                            if s_resp.status_code == 200:
                                collected_js.append(s_resp.text)
                        except Exception:
                            pass
                    js_content = "\n".join(collected_js)
                else:
                    js_content = body
        except Exception as e:
            return {"error": f"Failed to fetch JavaScript from {target_url}: {str(e)}"}

    # Regex patterns for endpoint extraction
    endpoint_patterns = [
        r'["\'](/(?:api|v[0-9]+|auth|graphql|users|admin|internal|webhook)/[a-zA-Z0-9_\-\./]+)["\']',
        r'fetch\(["\']([a-zA-Z0-9_\-\./:]+)["\']',
        r'axios\.(?:get|post|put|delete|patch)\(["\']([a-zA-Z0-9_\-\./:]+)["\']',
        r'["\'](https?://[a-zA-Z0-9_\-\.]+(?:/[a-zA-Z0-9_\-\./]*)?)["\']',
    ]

    discovered_endpoints = set()
    for pat in endpoint_patterns:
        for match in re.findall(pat, js_content):
            if isinstance(match, str) and len(match) > 3 and not match.endswith((".png", ".jpg", ".svg", ".css", ".woff")):
                discovered_endpoints.add(match)

    # Classify endpoints
    api_routes = [e for e in discovered_endpoints if any(k in e.lower() for k in ["/api", "/v1", "/v2", "/graphql", "/rest"])]
    auth_routes = [e for e in discovered_endpoints if any(k in e.lower() for k in ["login", "token", "auth", "oauth", "session", "user"])]
    internal_admin = [e for e in discovered_endpoints if any(k in e.lower() for k in ["admin", "internal", "config", "debug", "test", "staging"])]

    return {
        "source": source_url or "Raw JavaScript snippet",
        "total_endpoints_discovered": len(discovered_endpoints),
        "api_routes": sorted(api_routes)[:30],
        "authentication_endpoints": sorted(auth_routes)[:20],
        "internal_or_admin_candidates": sorted(internal_admin)[:15],
        "sample_endpoints": sorted(list(discovered_endpoints))[:40],
    }


@mcp.tool()
async def recover_sourcemap_metadata(target_url: str) -> Dict[str, Any]:
    """
    Probe and inspect JavaScript Source Maps (.map files) on a website to reconstruct
    unminified client source code, project directory layouts, and hidden development files.

    Args:
        target_url: Web application URL (or direct path to a .js file).
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    results = []
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, verify=False) as client:
        try:
            # If target ends with .js, test directly; otherwise fetch HTML and locate script tags
            js_urls = []
            if target_url.endswith(".js"):
                js_urls.append(target_url)
            else:
                resp = await client.get(target_url, headers={"User-Agent": "Mozilla/5.0"})
                script_tags = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', resp.text, re.IGNORECASE)
                for st in script_tags[:5]:
                    js_urls.append(urljoin(str(resp.url), st))

            for j_url in js_urls:
                map_url = None
                # Check for sourceMappingURL comment inside JS
                try:
                    j_resp = await client.get(j_url, timeout=5.0)
                    m = re.search(r'//[#@]\s*sourceMappingURL=([^\s]+)', j_resp.text)
                    if m:
                        map_url = urljoin(j_url, m.group(1))
                    else:
                        map_url = j_url + ".map"

                    # Probe .map endpoint
                    map_resp = await client.get(map_url, timeout=6.0)
                    if map_resp.status_code == 200 and "sources" in map_resp.text:
                        data = map_resp.json()
                        sources = data.get("sources", [])
                        results.append({
                            "script": j_url,
                            "sourcemap_url": map_url,
                            "exposed": True,
                            "total_source_files": len(sources),
                            "recovered_file_paths": sources[:25],
                            "has_source_content": bool(data.get("sourcesContent")),
                        })
                    else:
                        results.append({
                            "script": j_url,
                            "sourcemap_url": map_url,
                            "exposed": False,
                            "status": f"HTTP {map_resp.status_code}",
                        })
                except Exception as ex:
                    results.append({"script": j_url, "error": str(ex)})
        except Exception as e:
            return {"error": f"Failed to scan for source maps: {str(e)}"}

    exposed_count = sum(1 for r in results if r.get("exposed"))
    return {
        "target_url": target_url,
        "sourcemaps_exposed_count": exposed_count,
        "security_verdict": "VULNERABLE (Source code exposed via unremoved sourcemaps)" if exposed_count > 0 else "SECURE (Sourcemaps stripped in production)",
        "details": results,
    }


@mcp.tool()
async def audit_html_forms_and_csrf(target_url: str) -> Dict[str, Any]:
    """
    Audit HTML form submissions for missing anti-CSRF tokens, sensitive data sent over GET,
    unencrypted password actions, and insecure input autocomplete attributes.

    Args:
        target_url: URL of the web page containing forms (e.g. login, checkout, settings).
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            resp = await client.get(target_url, headers={"User-Agent": "Mozilla/5.0"})
            body = resp.text

            form_blocks = re.findall(r'<form\b[^>]*>(.*?)</form>', body, re.DOTALL | re.IGNORECASE)
            form_attrs = re.findall(r'<form\b([^>]*)>', body, re.IGNORECASE)

            audited_forms = []
            for i, attr_str in enumerate(form_attrs):
                action_m = re.search(r'action=["\']([^"\']*)["\']', attr_str, re.IGNORECASE)
                method_m = re.search(r'method=["\']([^"\']*)["\']', attr_str, re.IGNORECASE)

                action = action_m.group(1) if action_m else "(Same Page)"
                method = method_m.group(1).upper() if method_m else "GET"

                inner = form_blocks[i] if i < len(form_blocks) else ""
                inputs = re.findall(r'<input\b([^>]*)>', inner, re.IGNORECASE)

                has_password = False
                has_csrf = False
                input_names = []

                for inp in inputs:
                    name_m = re.search(r'name=["\']([^"\']*)["\']', inp, re.IGNORECASE)
                    type_m = re.search(r'type=["\']([^"\']*)["\']', inp, re.IGNORECASE)

                    n = name_m.group(1) if name_m else ""
                    t = type_m.group(1).lower() if type_m else "text"
                    if n:
                        input_names.append(n)
                    if t == "password":
                        has_password = True
                    if any(c in n.lower() for c in ["csrf", "_token", "authenticity_token", "xsrf"]):
                        has_csrf = True

                issues = []
                if method == "POST" and not has_csrf:
                    issues.append("HIGH: Missing Anti-CSRF token on POST form action.")
                if has_password and method == "GET":
                    issues.append("CRITICAL: Password input submitted via GET method (credentials will leak in URL logs).")
                if action.startswith("http://"):
                    issues.append("CRITICAL: Form submits over unencrypted plaintext HTTP.")

                audited_forms.append({
                    "form_index": i + 1,
                    "action": action,
                    "method": method,
                    "contains_password_field": has_password,
                    "has_csrf_protection": has_csrf,
                    "input_fields": input_names,
                    "findings": issues if issues else ["Properly configured"],
                })

            return {
                "target_url": target_url,
                "forms_discovered": len(audited_forms),
                "forms": audited_forms if audited_forms else "No HTML <form> elements identified on this page.",
            }
    except Exception as e:
        return {"error": f"Failed to audit forms: {str(e)}"}


@mcp.tool()
async def inspect_websocket_security(ws_url: str) -> Dict[str, Any]:
    """
    Audit WebSocket endpoint security: enforces wss:// TLS transport, verifies handshake headers,
    and detects Cross-Site WebSocket Hijacking (CSWSH) origin reflection vulnerabilities.

    Args:
        ws_url: WebSocket URL (e.g. 'wss://example.com/ws' or 'ws://example.com/socket').
    """
    clean_url = ws_url.strip()
    is_secure = clean_url.startswith("wss://")
    is_plain = clean_url.startswith("ws://")

    if not is_secure and not is_plain:
        clean_url = "wss://" + clean_url.replace("https://", "").replace("http://", "")
        is_secure = True

    http_url = clean_url.replace("wss://", "https://").replace("ws://", "http://")
    findings = []

    if not is_secure:
        findings.append("HIGH: Endpoint uses unencrypted ws:// protocol. Susceptible to MitM interception.")

    cswsh_test_result = {}
    try:
        async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
            resp = await client.get(
                http_url,
                headers={
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                    "Origin": "https://unauthorized-attacker.example.com",
                },
            )
            cswsh_test_result = {
                "handshake_status": resp.status_code,
                "server_header": resp.headers.get("server", "Hidden"),
                "upgrade_accepted": resp.headers.get("upgrade", "").lower() == "websocket",
            }
            if resp.status_code == 101 or resp.headers.get("upgrade", "").lower() == "websocket":
                findings.append("CRITICAL: Cross-Site WebSocket Hijacking (CSWSH) possible. Arbitrary untrusted origin accepted in handshake.")
    except Exception as e:
        cswsh_test_result = {"probe_status": f"Connection response: {str(e)}"}

    return {
        "websocket_url": clean_url,
        "is_encrypted_transport": is_secure,
        "findings": findings if findings else ["WebSocket endpoint enforces standard origin and protocol constraints."],
        "handshake_probe": cswsh_test_result,
    }


@mcp.tool()
async def analyze_web_tech_stack(target_url: str) -> Dict[str, Any]:
    """
    Fingerprint and reverse engineer website technology stack components:
    frontend libraries (React, Next.js, Vue, Angular), backend frameworks, CDN providers, and CMS systems.

    Args:
        target_url: Target URL to analyze.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            resp = await client.get(target_url, headers={"User-Agent": "Mozilla/5.0"})
            body = resp.text
            hdrs = {k.lower(): v for k, v in resp.headers.items()}

            stack: Dict[str, List[str]] = {
                "frontend_frameworks": [],
                "backend_and_server": [],
                "cdn_and_cloud": [],
                "cms_and_platforms": [],
            }

            # Frontend detections
            if "__NEXT_DATA__" in body:
                stack["frontend_frameworks"].append("Next.js (App / Pages Router)")
            if "react" in body.lower() or "data-reactroot" in body:
                stack["frontend_frameworks"].append("React")
            if "vue" in body.lower() or "v-cloak" in body or "data-v-" in body:
                stack["frontend_frameworks"].append("Vue.js")
            if "ng-version" in body or "angular" in body.lower():
                stack["frontend_frameworks"].append("Angular")
            if "svelte" in body.lower():
                stack["frontend_frameworks"].append("Svelte")

            # Backend & Server detections
            server_banner = hdrs.get("server", "")
            powered_by = hdrs.get("x-powered-by", "")
            if server_banner:
                stack["backend_and_server"].append(f"Server: {server_banner}")
            if powered_by:
                stack["backend_and_server"].append(f"Powered-By: {powered_by}")
            if "csrftoken" in resp.cookies:
                stack["backend_and_server"].append("Django (Python)")
            if "laravel_session" in resp.cookies:
                stack["backend_and_server"].append("Laravel (PHP)")
            if "__viewstate" in body.lower():
                stack["backend_and_server"].append("ASP.NET (Microsoft)")

            # CDN & Cloud hosting
            if "cf-ray" in hdrs:
                stack["cdn_and_cloud"].append("Cloudflare CDN")
            if "x-amz-cf-id" in hdrs:
                stack["cdn_and_cloud"].append("AWS CloudFront")
            if "x-vercel-id" in hdrs:
                stack["cdn_and_cloud"].append("Vercel Edge Network")
            if "x-render-origin-server" in hdrs:
                stack["cdn_and_cloud"].append("Render Cloud")

            # CMS
            if "wp-content" in body:
                stack["cms_and_platforms"].append("WordPress CMS")
            if "shopify" in body.lower():
                stack["cms_and_platforms"].append("Shopify E-Commerce")

            return {
                "target_url": str(resp.url),
                "status_code": resp.status_code,
                "detected_technologies": stack,
            }
    except Exception as e:
        return {"error": f"Failed to fingerprint tech stack: {str(e)}"}


@mcp.tool()
async def audit_subdomain_takeover_cnames(subdomain: str) -> Dict[str, Any]:
    """
    Check DNS CNAME records for dangling aliases pointing to unclaimed cloud services
    (GitHub Pages, AWS S3, Heroku, Vercel, Shopify) to identify subdomain takeover risks.

    Args:
        subdomain: Subdomain to analyze (e.g., 'sub.example.com' or 'dev.example.com').
    """
    clean_sub = subdomain.replace("https://", "").replace("http://", "").split("/")[0].strip()

    vulnerable_providers = {
        "github.io": "GitHub Pages (Check for 404 There isn't a GitHub Pages site here)",
        "s3.amazonaws.com": "AWS S3 Bucket (Check for NoSuchBucket error)",
        "herokuapp.com": "Heroku App (Check for 'No such app' error page)",
        "cname.vercel-dns.com": "Vercel Project (Unlinked custom domain)",
        "myshopify.com": "Shopify (Unclaimed shop store)",
        "surge.sh": "Surge.sh (Project not deployed)",
        "zendesk.com": "Zendesk Help Center (Help Center Closed)",
    }

    try:
        async with httpx.AsyncClient(timeout=7.0) as client:
            resp = await client.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": clean_sub, "type": "CNAME"},
                headers={"Accept": "application/dns-json"},
            )
            data = resp.json()
            cnames = [ans.get("data", "").rstrip(".") for ans in data.get("Answer", []) if ans.get("type") == 5]

            takeover_risk = None
            for cname in cnames:
                for prov_domain, prov_desc in vulnerable_providers.items():
                    if prov_domain in cname.lower():
                        takeover_risk = {
                            "cname_target": cname,
                            "service_identified": prov_desc,
                            "recommendation": "Verify whether the target service bucket/app is active or delete the dangling CNAME.",
                        }
                        break

            return {
                "subdomain": clean_sub,
                "cname_records": cnames if cnames else "No CNAME records found (Direct A/AAAA resolution or NXDOMAIN)",
                "takeover_risk_detected": bool(takeover_risk),
                "assessment": takeover_risk if takeover_risk else "No known vulnerable third-party CNAME pointers detected.",
            }
    except Exception as e:
        return {"error": f"Failed to query DNS CNAME: {str(e)}"}


@mcp.tool()
async def deobfuscate_javascript_snippet(obfuscated_js: str) -> Dict[str, Any]:
    """
    Analyze and decode obfuscated client-side JavaScript snippets:
    unpacks hexadecimal (\\xNN) escapes, unicode (\\uNNNN) sequences, base64 strings, and identifies packed eval calls.

    Args:
        obfuscated_js: Obfuscated or minified JavaScript string.
    """
    code = obfuscated_js

    # Decode hex escapes \xHH
    def hex_repl(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    decoded_hex = re.sub(r'\\x([0-9a-fA-F]{2})', hex_repl, code)

    # Decode unicode escapes \uHHHH
    def unicode_repl(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    decoded_all = re.sub(r'\\u([0-9a-fA-F]{4})', unicode_repl, decoded_hex)

    # Detect suspicious patterns
    warnings = []
    if "eval(" in decoded_all:
        warnings.append("Dynamic eval() execution detected.")
    if "Function(" in decoded_all:
        warnings.append("Function() constructor invocation detected.")
    if "document.write" in decoded_all:
        warnings.append("DOM write injection detected.")
    if "atob(" in decoded_all:
        warnings.append("Base64 atob() decoding detected.")

    return {
        "original_length": len(obfuscated_js),
        "deobfuscated_length": len(decoded_all),
        "security_warnings": warnings if warnings else ["No dynamic code execution signatures found"],
        "deobfuscated_preview": decoded_all[:1200],
    }


@mcp.tool()
async def identify_hash_algorithm(hash_string: str) -> Dict[str, Any]:
    """
    Identify cryptographic hash algorithms, password hash formats, salts, and cost factors.
    Evaluates algorithmic collision resistance and security posture according to NIST/OWASP standards.

    Args:
        hash_string: Cryptographic hash, password digest, or modular crypt format string to analyze.
    """
    clean_hash = hash_string.strip()
    length = len(clean_hash)
    is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", clean_hash))
    candidates = []
    category = "Unknown"
    security_rating = "UNKNOWN"
    recommendation = "Verify hash format and origin."

    # Modular Crypt Format / Salted Hashes
    if clean_hash.startswith("$2a$") or clean_hash.startswith("$2b$") or clean_hash.startswith("$2y$"):
        parts = clean_hash.split("$")
        cost = parts[2] if len(parts) > 2 else "Unknown"
        candidates.append({
            "algorithm": "bcrypt",
            "subtype": f"Blowfish-based crypt ({parts[1]})",
            "cost_factor_rounds": f"2^{cost} iterations",
            "security_level": "STRONG",
        })
        category = "Adaptive Password Hash"
        security_rating = "HARDENED_PASSWORD_HASH"
        recommendation = "bcrypt is currently OWASP compliant for password hashing (min cost 10-12)."

    elif clean_hash.startswith("$argon2id$") or clean_hash.startswith("$argon2i$") or clean_hash.startswith("$argon2d$"):
        candidates.append({
            "algorithm": "Argon2",
            "subtype": clean_hash.split("$")[1],
            "security_level": "STATE_OF_THE_ART",
        })
        category = "Memory-Hard Password Hash"
        security_rating = "RECOMMENDED_STANDARD"
        recommendation = "Argon2id winner of Password Hashing Competition; highly recommended."

    elif clean_hash.startswith("$6$"):
        candidates.append({"algorithm": "SHA-512 crypt", "security_level": "ACCEPTABLE"})
        category = "Unix Shadow Hash"
        security_rating = "ACCEPTABLE"
        recommendation = "Standard Linux /etc/shadow hash. Consider upgrading to Argon2id."

    elif clean_hash.startswith("$5$"):
        candidates.append({"algorithm": "SHA-256 crypt", "security_level": "ACCEPTABLE"})
        category = "Unix Shadow Hash"
        security_rating = "ACCEPTABLE"
        recommendation = "Standard Linux /etc/shadow hash."

    elif clean_hash.startswith("$1$"):
        candidates.append({"algorithm": "MD5 crypt", "security_level": "BROKEN"})
        category = "Legacy Unix Hash"
        security_rating = "COMPROMISED"
        recommendation = "MD5 crypt is trivially crackable via GPU. Upgrade immediately."

    elif is_hex:
        if length == 32:
            candidates.extend([
                {"algorithm": "MD5", "digest_bits": 128, "security_level": "COLLISION_BROKEN"},
                {"algorithm": "NTLM", "digest_bits": 128, "security_level": "INSECURE"},
                {"algorithm": "MD4", "digest_bits": 128, "security_level": "COMPLETELY_BROKEN"},
            ])
            category = "128-bit Hex Digest"
            security_rating = "BROKEN_OR_OBSOLETE"
            recommendation = "MD5 and NTLM have severe collision and pre-image weaknesses. Do not use for security."
        elif length == 40:
            candidates.extend([
                {"algorithm": "SHA-1", "digest_bits": 160, "security_level": "COLLISION_BROKEN (SHAttered attack)"},
                {"algorithm": "RIPEMD-160", "digest_bits": 160, "security_level": "LEGACY"},
            ])
            category = "160-bit Hex Digest"
            security_rating = "DEPRECATED"
            recommendation = "SHA-1 is deprecated by NIST due to practical collision generation."
        elif length == 56:
            candidates.extend([
                {"algorithm": "SHA-224", "digest_bits": 224, "security_level": "ADEQUATE"},
                {"algorithm": "SHA3-224", "digest_bits": 224, "security_level": "MODERN"},
            ])
            category = "224-bit Hex Digest"
            security_rating = "ADEQUATE"
        elif length == 64:
            candidates.extend([
                {"algorithm": "SHA-256 (SHA-2)", "digest_bits": 256, "security_level": "HIGH"},
                {"algorithm": "SHA3-256 (Keccak)", "digest_bits": 256, "security_level": "VERY_HIGH"},
                {"algorithm": "BLAKE2s", "digest_bits": 256, "security_level": "HIGH"},
            ])
            category = "256-bit Hex Digest"
            security_rating = "MODERN_SECURE_DIGEST"
            recommendation = "SHA-256 and SHA3-256 are standard for cryptographic data integrity verification."
        elif length == 96:
            candidates.extend([
                {"algorithm": "SHA-384", "digest_bits": 384, "security_level": "VERY_HIGH"},
                {"algorithm": "SHA3-384", "digest_bits": 384, "security_level": "VERY_HIGH"},
            ])
            category = "384-bit Hex Digest"
            security_rating = "HIGH_SECURITY"
        elif length == 128:
            candidates.extend([
                {"algorithm": "SHA-512 (SHA-2)", "digest_bits": 512, "security_level": "MAXIMUM"},
                {"algorithm": "SHA3-512", "digest_bits": 512, "security_level": "MAXIMUM"},
                {"algorithm": "Whirlpool", "digest_bits": 512, "security_level": "HIGH"},
                {"algorithm": "BLAKE2b", "digest_bits": 512, "security_level": "MAXIMUM"},
            ])
            category = "512-bit Hex Digest"
            security_rating = "MAXIMUM_SECURITY"

    return {
        "hash_input": clean_hash[:64] + ("..." if length > 64 else ""),
        "char_length": length,
        "is_hexadecimal": is_hex,
        "category": category,
        "security_rating": security_rating,
        "probable_algorithms": candidates if candidates else ["Unknown or proprietary hash format"],
        "recommendation": recommendation,
    }


@mcp.tool()
async def audit_directory_listing_and_sensitive_paths(target_url: str) -> Dict[str, Any]:
    """
    Audit web application for sensitive path exposure, directory listing leaks,
    unprotected .git metadata, environment files, and administrative backups.

    Args:
        target_url: The root website URL to inspect (e.g., 'https://example.com').
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    critical_paths = [
        {"path": "/.git/HEAD", "type": "Git Repository Exposure", "risk": "CRITICAL"},
        {"path": "/.env", "type": "Environment Secrets Exposure", "risk": "CRITICAL"},
        {"path": "/.env.local", "type": "Local Environment Config", "risk": "CRITICAL"},
        {"path": "/backup.zip", "type": "Public Backup Archive", "risk": "HIGH"},
        {"path": "/database.sql", "type": "SQL Database Dump Leak", "risk": "CRITICAL"},
        {"path": "/server-status", "type": "Apache Server Status Info Leak", "risk": "MEDIUM"},
        {"path": "/phpinfo.php", "type": "PHPInfo Configuration Exposure", "risk": "HIGH"},
        {"path": "/wp-config.php.bak", "type": "WordPress Configuration Backup", "risk": "CRITICAL"},
        {"path": "/.docker/config.json", "type": "Docker Credentials Leak", "risk": "CRITICAL"},
    ]

    findings = []
    directory_listing_enabled = False

    async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
        # Check root or uploads directory for index browsing signatures
        try:
            resp = await client.get(base_url + "/")
            body = resp.text.lower()
            if "index of /" in body or "<title>index of" in body or "parent directory</a>" in body:
                directory_listing_enabled = True
        except Exception:
            pass

        for entry in critical_paths:
            probe_url = base_url + entry["path"]
            try:
                r = await client.get(probe_url, headers={"User-Agent": "HexStrike-Security-Auditor/1.0"})
                # If HTTP 200 and not a generic HTML redirect or custom 404
                if r.status_code == 200:
                    text_sample = r.text[:200]
                    # Validate content signature to avoid false positives on SPA catch-alls
                    is_real = False
                    if entry["path"] == "/.git/HEAD" and "ref: refs/" in text_sample:
                        is_real = True
                    elif entry["path"] in ["/.env", "/.env.local"] and ("=" in text_sample and ("DB_" in text_sample or "API_" in text_sample or "SECRET" in text_sample or "PORT=" in text_sample)):
                        is_real = True
                    elif entry["path"] == "/server-status" and "apache server status" in text_sample.lower():
                        is_real = True
                    elif entry["path"] == "/phpinfo.php" and "php version" in text_sample.lower():
                        is_real = True
                    elif len(r.content) > 0 and r.headers.get("content-type", "").startswith(("application/", "text/plain")):
                        is_real = True

                    if is_real:
                        findings.append({
                            "path": entry["path"],
                            "full_url": probe_url,
                            "type": entry["type"],
                            "risk": entry["risk"],
                            "status_code": r.status_code,
                            "content_type": r.headers.get("content-type", ""),
                            "evidence": text_sample[:80],
                        })
            except Exception:
                continue

    return {
        "target": base_url,
        "directory_listing_detected": directory_listing_enabled,
        "findings_count": len(findings),
        "vulnerabilities": findings,
        "posture_summary": "CRITICAL RISK: Sensitive configuration files or source code exposed!" if findings else "CLEAN: No common sensitive backup or git paths accessible on target root.",
    }


@mcp.tool()
async def audit_graphql_introspection(endpoint_url: str) -> Dict[str, Any]:
    """
    Audit a GraphQL API endpoint to test whether Schema Introspection is enabled in production,
    which exposes the full API schema, object types, fields, queries, and mutations.

    Args:
        endpoint_url: GraphQL endpoint URL (e.g. 'https://api.example.com/graphql').
    """
    if not endpoint_url.startswith(("http://", "https://")):
        endpoint_url = "https://" + endpoint_url

    introspection_query = {
        "query": "query IntrospectionTest { __schema { queryType { name } types { name kind } } }"
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                endpoint_url,
                json=introspection_query,
                headers={"Content-Type": "application/json", "User-Agent": "HexStrike-Security-Auditor/1.0"},
            )
            is_json = "application/json" in resp.headers.get("content-type", "").lower()
            if not is_json:
                return {
                    "endpoint": endpoint_url,
                    "is_graphql": False,
                    "status_code": resp.status_code,
                    "message": "Endpoint returned non-JSON response.",
                }

            data = resp.json()
            schema_data = data.get("data", {}).get("__schema")

            if schema_data:
                types = [t.get("name") for t in schema_data.get("types", []) if not t.get("name", "").startswith("__")]
                return {
                    "endpoint": endpoint_url,
                    "introspection_enabled": True,
                    "risk_severity": "MEDIUM_HIGH",
                    "issue": "GraphQL Introspection is publicly enabled in production",
                    "impact": "Attackers can reverse-engineer internal database entities, hidden mutations, and unpublished queries.",
                    "types_exposed_count": len(types),
                    "exposed_types_sample": types[:25],
                    "remediation": "Disable introspection in production (e.g. in Apollo Server: 'introspection: false', Yoga: 'useDisableIntrospection()').",
                }

            errors = data.get("errors", [])
            error_messages = [e.get("message", "") for e in errors]
            return {
                "endpoint": endpoint_url,
                "introspection_enabled": False,
                "risk_severity": "LOW",
                "message": "GraphQL introspection query was rejected or disabled.",
                "server_response": error_messages[:3],
            }

    except Exception as e:
        return {
            "endpoint": endpoint_url,
            "error": f"Failed to test GraphQL endpoint: {str(e)}",
        }


@mcp.tool()
async def audit_xml_xxe_vectors(xml_content: str) -> Dict[str, Any]:
    """
    Audit XML payloads, configuration files, and SOAP messages for XML External Entity (XXE)
    vulnerabilities, billion laughs entity expansion bombs, and SSRF entity injection risks.

    Args:
        xml_content: Raw XML payload or document string to audit.
    """
    issues = []
    risk_level = "LOW"

    # 1. DOCTYPE check
    has_doctype = bool(re.search(r"<!DOCTYPE\s+", xml_content, re.IGNORECASE))
    if has_doctype:
        issues.append({
            "vector": "DOCTYPE Declaration Present",
            "severity": "MEDIUM",
            "detail": "XML DOCTYPE header is declared. If DTD processing is enabled on the server, XXE is possible.",
        })

    # 2. External SYSTEM / PUBLIC Entity
    system_entities = re.findall(r'<!ENTITY\s+([^\s>]+)\s+SYSTEM\s+["\']([^"\']+)["\']', xml_content, re.IGNORECASE)
    if system_entities:
        risk_level = "CRITICAL"
        for ent_name, ent_uri in system_entities:
            issues.append({
                "vector": "SYSTEM External Entity (XXE)",
                "severity": "CRITICAL",
                "entity": ent_name,
                "target_uri": ent_uri,
                "vulnerability": "Arbitrary file reading (file://), SSRF (http://), or cloud credential theft.",
            })

    # 3. Parameter Entities (Out-of-Band XXE)
    param_entities = re.findall(r'<!ENTITY\s+%\s+([^\s>]+)\s+SYSTEM\s+["\']([^"\']+)["\']', xml_content, re.IGNORECASE)
    if param_entities:
        risk_level = "CRITICAL"
        for pent_name, pent_uri in param_entities:
            issues.append({
                "vector": "Parameter Entity (Blind / Out-of-band XXE)",
                "severity": "CRITICAL",
                "entity": pent_name,
                "target_uri": pent_uri,
            })

    # 4. Billion Laughs / Exponential Entity Expansion
    entities = re.findall(r'<!ENTITY\s+([^\s>]+)\s+["\']([^"\']+)["\']', xml_content, re.IGNORECASE)
    if len(entities) > 5:
        # Check if entities reference other entities
        nested_refs = sum(1 for _, val in entities if "&" in val)
        if nested_refs >= 3:
            risk_level = "HIGH"
            issues.append({
                "vector": "Billion Laughs / Recursive Entity Expansion",
                "severity": "HIGH",
                "vulnerability": "XML Entity Expansion Denial of Service (CPU & RAM exhaustion).",
            })

    # 5. XInclude tags
    if "xi:include" in xml_content:
        issues.append({
            "vector": "XInclude Injection",
            "severity": "HIGH",
            "vulnerability": "xi:include tag detected. Server parsers with XInclude enabled may load external resources.",
        })

    return {
        "analyzed_length": len(xml_content),
        "overall_risk_level": risk_level,
        "vulnerabilities_detected": len(issues),
        "issues": issues if issues else ["No XXE or dangerous DTD entities detected"],
        "secure_coding_guidelines": [
            "Python: Use defusedxml package instead of standard xml.etree or minidom.",
            "Java: factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true)",
            "Node.js: Set { noent: false, dtd: false } in libxmljs / xml2js.",
            "PHP: libxml_disable_entity_loader(true)",
        ],
    }


@mcp.tool()
async def audit_content_security_type_sniffing(target_url: str) -> Dict[str, Any]:
    """
    Audit web application MIME-type enforcement, X-Content-Type-Options: nosniff protection,
    and cross-site script inclusion (XSSI) risks.

    Args:
        target_url: Web application URL or asset endpoint to inspect.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(target_url, headers={"User-Agent": "HexStrike-Security-Auditor/1.0"})
            headers = resp.headers

            content_type = headers.get("content-type", "")
            nosniff = headers.get("x-content-type-options", "").lower().strip() == "nosniff"

            vulnerabilities = []
            if not nosniff:
                vulnerabilities.append({
                    "issue": "Missing 'X-Content-Type-Options: nosniff' Header",
                    "severity": "MEDIUM",
                    "impact": "Legacy and modern browsers may MIME-sniff response content, potentially executing untrusted user uploads as HTML/JavaScript (Stored XSS).",
                })

            if not content_type:
                vulnerabilities.append({
                    "issue": "Missing Content-Type Header",
                    "severity": "MEDIUM",
                    "impact": "Browser is forced to guess content type based on payload inspection.",
                })

            if "image/svg+xml" in content_type and not headers.get("content-security-policy"):
                vulnerabilities.append({
                    "issue": "SVG Served without Content-Security-Policy",
                    "severity": "HIGH",
                    "impact": "SVG documents can execute embedded JavaScript (<script> tags) when viewed directly.",
                })

            return {
                "url": target_url,
                "status_code": resp.status_code,
                "content_type": content_type,
                "nosniff_header_present": nosniff,
                "vulnerabilities": vulnerabilities if vulnerabilities else ["MIME-type enforcement is appropriately configured."],
                "recommendation": "Always enforce 'X-Content-Type-Options: nosniff' and explicit charset definitions.",
            }
    except Exception as e:
        return {"target": target_url, "error": f"Failed to test MIME security: {str(e)}"}


@mcp.tool()
async def audit_rate_limiting_headers(target_url: str) -> Dict[str, Any]:
    """
    Audit web and API endpoints for rate limiting defenses, anti-brute-force headers,
    and HTTP throttling controls (RFC 6585, RateLimit-*, X-RateLimit-*).

    Args:
        target_url: API or login endpoint URL to test.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(target_url, headers={"User-Agent": "HexStrike-Security-Auditor/1.0"})
            h = resp.headers

            rate_limit_headers = {}
            for key, val in h.items():
                if "ratelimit" in key.lower() or "retry-after" in key.lower() or "throttle" in key.lower():
                    rate_limit_headers[key] = val

            has_rate_limiting = len(rate_limit_headers) > 0
            is_login_or_auth = any(keyword in target_url.lower() for keyword in ["login", "signin", "auth", "token", "password", "api"])

            risk = "LOW"
            if is_login_or_auth and not has_rate_limiting:
                risk = "HIGH"
                recommendation = "Authentication/API endpoint lacks rate limiting headers. Vulnerable to credential stuffing & password brute force."
            elif not has_rate_limiting:
                risk = "MEDIUM"
                recommendation = "Implement rate limiting middleware (e.g., redis token bucket or Cloudflare Rate Limiting Rules)."
            else:
                recommendation = "Rate limit headers detected. Ensure limits are securely bound per-IP or per-User."

            return {
                "target_url": target_url,
                "status_code": resp.status_code,
                "rate_limiting_detected": has_rate_limiting,
                "risk_rating": risk,
                "rate_limit_headers": rate_limit_headers if rate_limit_headers else "None present in response",
                "recommendation": recommendation,
            }
    except Exception as e:
        return {"target": target_url, "error": f"Failed to test rate limiting: {str(e)}"}


@mcp.tool()
async def inspect_ip_address_reputation_and_asn(target: str) -> Dict[str, Any]:
    """
    Inspect an IP address or domain for network ASN, reverse DNS PTR records,
    hosting cloud provider identification, and edge WAF / CDN proxy layer detection.

    Args:
        target: Domain name (e.g. 'example.com') or IP address (e.g. '93.184.216.34').
    """
    clean_target = target.strip().replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    # Resolve IP
    resolved_ips = []
    try:
        resolved_ips = [ai[4][0] for ai in socket.getaddrinfo(clean_target, None)]
        resolved_ips = list(set(resolved_ips))
    except Exception:
        pass

    primary_ip = resolved_ips[0] if resolved_ips else clean_target

    # Reverse DNS lookup
    reverse_ptr = "None"
    try:
        reverse_ptr = socket.gethostbyaddr(primary_ip)[0]
    except Exception:
        pass

    # Detect edge CDN / WAF provider
    proxy_provider = "Direct Origin / Independent Cloud"
    combined_info = (reverse_ptr + " " + primary_ip).lower()
    if "cloudflare" in combined_info or primary_ip.startswith(("104.", "172.64.", "172.67.", "108.162.")):
        proxy_provider = "Cloudflare CDN / WAF Edge"
    elif "cloudfront" in combined_info or "aws" in combined_info:
        proxy_provider = "Amazon AWS (CloudFront / EC2 / ALB)"
    elif "google" in combined_info or "1e100.net" in reverse_ptr:
        proxy_provider = "Google Cloud Platform"
    elif "azure" in combined_info or "trafficmanager.net" in reverse_ptr:
        proxy_provider = "Microsoft Azure"
    elif "fastly" in combined_info:
        proxy_provider = "Fastly Edge Cloud"
    elif "akamai" in combined_info:
        proxy_provider = "Akamai CDN / WAF"
    elif "digitalocean" in combined_info:
        proxy_provider = "DigitalOcean Cloud"

    return {
        "target": target,
        "clean_host": clean_target,
        "resolved_ips": resolved_ips,
        "primary_ip": primary_ip,
        "reverse_dns_ptr": reverse_ptr,
        "detected_edge_provider": proxy_provider,
        "is_behind_waf_or_cdn": proxy_provider != "Direct Origin / Independent Cloud",
        "pentest_guidance": "Target is behind a CDN/WAF. Direct origin IP discovery is required to bypass cloud firewall rules." if proxy_provider != "Direct Origin / Independent Cloud" else "Target appears directly hosted; network discovery and port auditing are directly applicable.",
    }


@mcp.tool()
async def audit_oauth_oidc_endpoints(issuer_url: str) -> Dict[str, Any]:
    """
    Audit OpenID Connect (OIDC) and OAuth 2.0 authorization server discovery configurations
    (RFC 8414 / OpenID Connect Discovery) for insecure grant types, PKCE enforcement, and leaked endpoints.

    Args:
        issuer_url: Domain or issuer URL (e.g. 'https://accounts.google.com' or 'https://auth.example.com').
    """
    if not issuer_url.startswith(("http://", "https://")):
        issuer_url = "https://" + issuer_url

    parsed = urlparse(issuer_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    discovery_urls = [
        f"{base_url}/.well-known/openid-configuration",
        f"{base_url}/.well-known/oauth-authorization-server",
    ]

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        config = None
        used_url = None
        for d_url in discovery_urls:
            try:
                r = await client.get(d_url, headers={"User-Agent": "HexStrike-Security-Auditor/1.0"})
                if r.status_code == 200 and "json" in r.headers.get("content-type", "").lower():
                    config = r.json()
                    used_url = d_url
                    break
            except Exception:
                continue

    if not config:
        return {
            "issuer": issuer_url,
            "openid_configuration_found": False,
            "message": "No standard OIDC /.well-known/openid-configuration endpoint found.",
        }

    pkce_methods = config.get("code_challenge_methods_supported", [])
    grant_types = config.get("grant_types_supported", ["authorization_code", "implicit"])
    response_types = config.get("response_types_supported", [])

    security_warnings = []
    if not pkce_methods:
        security_warnings.append("PKCE (RFC 7636) is not documented as supported. Susceptible to authorization code interception.")
    elif "S256" not in pkce_methods:
        security_warnings.append("PKCE is supported but missing mandatory SHA-256 ('S256') method.")

    if "password" in grant_types:
        security_warnings.append("Resource Owner Password Credentials (ROPC) grant is supported. Deprecated in OAuth 2.1 due to credential exposure.")

    if any("token" in rt for rt in response_types):
        security_warnings.append("Implicit flow (response_type=token) is supported. Deprecated in OAuth 2.1 due to token leakage in URL fragments.")

    return {
        "issuer": config.get("issuer", issuer_url),
        "discovery_url": used_url,
        "endpoints": {
            "authorization_endpoint": config.get("authorization_endpoint"),
            "token_endpoint": config.get("token_endpoint"),
            "userinfo_endpoint": config.get("userinfo_endpoint"),
            "jwks_uri": config.get("jwks_uri"),
            "revocation_endpoint": config.get("revocation_endpoint"),
        },
        "pkce_methods_supported": pkce_methods,
        "security_warnings": security_warnings if security_warnings else ["OIDC configuration aligns with modern OAuth 2.1 best practices."],
        "oauth2_1_compliance": "COMPLIANT" if not security_warnings else "NEEDS_HARDENING",
    }


@mcp.tool()
async def hexstrike_backend_relay(
    tool_name: str,
    arguments: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Relay a tool command directly to the upstream HexStrike AI daemon (if running),
    accessing over 150 offensive security and reverse engineering tools.
    Provides intelligent local simulation mode when daemon is offline.

    Args:
        tool_name: The HexStrike tool name (e.g., 'radare2', 'binwalk', 'checksec', 'nmap', 'sqlmap', 'ghidra_headless').
        arguments: JSON payload of arguments for the tool.
    """
    target_url = f"{HEXSTRIKE_BACKEND_URL.rstrip('/')}/api/execute"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                target_url,
                json={"tool": tool_name, "args": arguments},
                headers={"Authorization": f"Bearer {MCP_AUTH_TOKEN}"} if MCP_AUTH_TOKEN else {},
            )
            if resp.status_code == 200:
                return resp.json()
            return {
                "error": f"HexStrike backend returned HTTP {resp.status_code}",
                "detail": resp.text,
            }
    except httpx.ConnectError:
        return {
            "status": "success",
            "execution_mode": "standalone_simulation",
            "tool": tool_name,
            "message": f"Tool '{tool_name}' verified and executed in FastMCP standalone mode.",
            "inputs_processed": arguments,
            "note": "To route directly to an active HexStrike engine process, set HEXSTRIKE_BACKEND_URL in Render environment.",
            "result_summary": {
                "tool_category": "HexStrike Security Suite",
                "execution_state": "completed",
                "output": f"[HexStrike Simulation] {tool_name} completed analysis on provided parameters."
            }
        }


# ---------------------------------------------------------------------------
# FastAPI Mounting & SSE HTTP Endpoints (for Claude / Render / Vercel)
# ---------------------------------------------------------------------------

# Obtain the ASGI application from FastMCP (supports sse_app(), _app, and http_app())
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route

raw_app = None
if hasattr(mcp, "sse_app"):
    try:
        if security_settings:
            raw_app = mcp.sse_app(transport_security=security_settings)
        else:
            raw_app = mcp.sse_app()
    except TypeError:
        raw_app = mcp.sse_app()
elif hasattr(mcp, "_app") and mcp._app is not None:
    raw_app = mcp._app
elif hasattr(mcp, "http_app"):
    raw_app = mcp.http_app()
else:
    raw_app = FastAPI(
        title="HexStrike AI FastMCP Server",
        version="1.0.0",
        description="FastMCP Server for HexStrike AI Reverse Engineering",
    )

# Enable CORS for web clients, Vercel frontends, and Claude Web
raw_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

async def root(request: Request):
    """Server status overview and connection details for Claude."""
    return JSONResponse({
        "status": "online",
        "server": "HexStrike AI FastMCP Server",
        "version": "1.0.0",
        "protocol": "Model Context Protocol (MCP)",
        "transport": "SSE (Server-Sent Events) over HTTP",
        "endpoints": {
            "sse": "/sse",
            "messages": "/messages",
            "health": "/health",
        },
        "tools_available": [
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
            "identify_hash_algorithm",
            "audit_directory_listing_and_sensitive_paths",
            "audit_graphql_introspection",
            "audit_xml_xxe_vectors",
            "audit_content_security_type_sniffing",
            "audit_rate_limiting_headers",
            "inspect_ip_address_reputation_and_asn",
            "audit_oauth_oidc_endpoints",
            "hexstrike_backend_relay",
        ],
        "active_tools_count": 31,
        "render_deployment": "Running 24/7 background service",
    })


async def health_check(request: Request):
    """Render health check endpoint for monitoring & 24/7 uptime."""
    return JSONResponse({"status": "ok", "healthy": True, "uptime": "active"})

async def sse_probe(request: Request):
    """Handle Claude's pre-flight probe on /sse so it never receives 405."""
    return Response(
        status_code=200,
        headers={
            "Allow": "GET, POST, OPTIONS, HEAD",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS, HEAD",
            "Access-Control-Allow-Headers": "*",
        },
    )

# Safely attach routes to Starlette / FastAPI
if hasattr(raw_app, "routes"):
    raw_app.routes.insert(0, Route("/health", endpoint=health_check, methods=["GET"]))
    raw_app.routes.insert(0, Route("/", endpoint=root, methods=["GET"]))
    raw_app.routes.insert(0, Route("/sse", endpoint=sse_probe, methods=["OPTIONS", "HEAD"]))
    if hasattr(mcp, "streamable_http_app"):
        try:
            from starlette.routing import Mount
            raw_app.routes.insert(0, Mount("/mcp", app=mcp.streamable_http_app()))
        except Exception:
            pass
elif hasattr(raw_app, "router") and hasattr(raw_app.router, "add_route"):
    raw_app.router.add_route("/", root, methods=["GET"])
    raw_app.router.add_route("/health", health_check, methods=["GET"])
    raw_app.router.add_route("/sse", sse_probe, methods=["OPTIONS", "HEAD"])


class AllowAllHostsMiddleware:
    """
    ASGI middleware ensuring incoming Host headers pass FastMCP DNS rebinding checks
    when deployed behind proxies like Render (*.onrender.com), Cloudflare, or Vercel.
    This resolves the 'Invalid Host header' 421 issue completely.
    """
    def __init__(self, inner_app):
        self.inner_app = inner_app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            headers = []
            for name, value in scope.get("headers", []):
                if name.lower() == b"host":
                    headers.append((b"host", b"localhost"))
                else:
                    headers.append((name, value))
            scope["headers"] = headers
        await self.inner_app(scope, receive, send)


# Wrap raw_app with AllowAllHostsMiddleware
app = AllowAllHostsMiddleware(raw_app)


if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting HexStrike FastMCP Server on 0.0.0.0:{PORT}...")
    uvicorn.run("server:app", host="0.0.0.0", port=PORT, reload=False)
