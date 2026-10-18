// Interactive Reverse Engineering Engine in TypeScript
// Powers the browser-based tool testing console

export interface DisasmInsn {
  address: string;
  bytes: string;
  mnemonic: string;
  op_str: string;
}

export function parseHexOrBase64ToBytes(input: string): Uint8Array | null {
  const clean = input.trim();
  if (!clean) return null;

  // Try parsing as Hex
  const hexClean = clean.replace(/[\s\r\n0x]/g, "");
  if (/^[0-9a-fA-F]+$/.test(hexClean) && hexClean.length % 2 === 0) {
    const bytes = new Uint8Array(hexClean.length / 2);
    for (let i = 0; i < hexClean.length; i += 2) {
      bytes[i / 2] = parseInt(hexClean.substring(i, i + 2), 16);
    }
    return bytes;
  }

  // Try parsing as Base64
  try {
    const binaryString = atob(clean);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

export function calculateEntropy(bytes: Uint8Array): {
  entropy: number;
  verdict: string;
  packers: string[];
  blockMap: { offset: string; entropy: number; status: string }[];
} {
  if (bytes.length === 0) {
    return { entropy: 0, verdict: "Empty payload", packers: [], blockMap: [] };
  }

  const counts: Record<number, number> = {};
  for (let i = 0; i < bytes.length; i++) {
    counts[bytes[i]] = (counts[bytes[i]] || 0) + 1;
  }

  let ent = 0;
  const len = bytes.length;
  for (const byteVal in counts) {
    const p = counts[byteVal] / len;
    ent -= p * Math.log2(p);
  }
  const entropy = Math.round(ent * 1000) / 1000;

  // Check known signatures
  const rawStr = Array.from(bytes)
    .map((b) => String.fromCharCode(b))
    .join("");

  const packers: string[] = [];
  if (rawStr.includes("UPX!") || rawStr.includes("UPX0")) packers.push("UPX Packer");
  if (rawStr.includes(".themida") || rawStr.includes("Themida")) packers.push("Themida / WinLicense");
  if (rawStr.includes(".vmp0") || rawStr.includes(".vmp1")) packers.push("VMProtect");
  if (rawStr.toLowerCase().includes("aspack")) packers.push("ASPack");

  let verdict = "Standard uncompressed machine code";
  if (packers.length > 0) {
    verdict = `Packer Signatures Detected: ${packers.join(", ")}`;
  } else if (entropy > 7.2) {
    verdict = "Very High Entropy (>7.2). Strong indication of encrypted payload or heavy packing.";
  } else if (entropy > 6.4) {
    verdict = "Elevated Entropy (>6.4). Likely compressed resources or obfuscated data.";
  }

  // Generate block map
  const blockSize = Math.max(32, Math.floor(bytes.length / 8));
  const blockMap = [];
  for (let i = 0; i < bytes.length; i += blockSize) {
    const chunk = bytes.slice(i, i + blockSize);
    const chunkCounts: Record<number, number> = {};
    for (let c = 0; c < chunk.length; c++) chunkCounts[chunk[c]] = (chunkCounts[chunk[c]] || 0) + 1;
    let chunkEnt = 0;
    for (const k in chunkCounts) {
      const p = chunkCounts[k] / chunk.length;
      chunkEnt -= p * Math.log2(p);
    }
    const ce = Math.round(chunkEnt * 100) / 100;
    blockMap.push({
      offset: `0x${i.toString(16).padStart(4, "0")}`,
      entropy: ce,
      status: ce > 7.1 ? "Packed/Encrypted" : ce > 4.0 ? "Normal Code" : "Low Entropy/Sparse",
    });
  }

  return { entropy, verdict, packers, blockMap };
}

export function inspectHeaders(bytes: Uint8Array): {
  format: string;
  architecture: string;
  endianness: string;
  bitness: string;
  magic: string;
  details: Record<string, string>;
  hexdump: string;
} {
  const magicHex = Array.from(bytes.slice(0, 8))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(" ");

  let format = "Unknown / Raw Payload";
  let architecture = "Generic";
  let endianness = "Little Endian";
  let bitness = "Unknown";
  const details: Record<string, string> = {};

  // Check ELF: 7F 45 4C 46
  if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
    format = "ELF (Executable and Linkable Format - Linux/Unix)";
    bitness = bytes[4] === 2 ? "64-bit (ELFCLASS64)" : bytes[4] === 1 ? "32-bit (ELFCLASS32)" : "Unknown";
    endianness = bytes[5] === 1 ? "Little Endian (ELFDATA2LSB)" : "Big Endian";
    const mach = bytes.length >= 20 ? (bytes[5] === 1 ? bytes[18] | (bytes[19] << 8) : (bytes[18] << 8) | bytes[19]) : 0;
    const machNames: Record<number, string> = {
      0x03: "x86 (Intel 80386)",
      0x3e: "Advanced Micro Devices X86-64",
      0x28: "ARM 32-bit",
      0xb7: "AArch64 (ARM 64-bit)",
      0x08: "MIPS",
      0xf3: "RISC-V",
    };
    architecture = machNames[mach] || `Other Architecture (0x${mach.toString(16)})`;
    details["OS ABI"] = bytes[7] === 0 ? "UNIX - System V" : `ABI 0x${bytes[7].toString(16)}`;
    details["Type"] = bytes[16] === 2 ? "ET_EXEC (Executable)" : bytes[16] === 3 ? "ET_DYN (Shared object / PIE)" : "Other";
  }
  // Check Windows MZ / PE: 4D 5A
  else if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
    format = "PE (Portable Executable - Windows)";
    bitness = "32 / 64-bit";
    const peOffset = bytes.length >= 64 ? bytes[60] | (bytes[61] << 8) | (bytes[62] << 16) | (bytes[63] << 24) : 0;
    if (bytes.length >= peOffset + 4 && bytes[peOffset] === 0x50 && bytes[peOffset + 1] === 0x45) {
      details["PE Signature Offset"] = `0x${peOffset.toString(16)}`;
      const mach = bytes.length >= peOffset + 6 ? bytes[peOffset + 4] | (bytes[peOffset + 5] << 8) : 0;
      architecture = mach === 0x8664 ? "x86_64 (AMD64)" : mach === 0x014c ? "x86 (i386)" : mach === 0xaa64 ? "ARM64" : `Machine 0x${mach.toString(16)}`;
    }
  }
  // Check Mach-O: FEEDFACE / FEEDFACF / CAFEBABE
  else if (
    (bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa) ||
    (bytes[0] === 0xcf && bytes[1] === 0xfa && bytes[2] === 0xed) ||
    (bytes[0] === 0xca && bytes[1] === 0xfe && bytes[2] === 0xba && bytes[3] === 0xbe)
  ) {
    format = "Mach-O (macOS / Darwin / iOS)";
    architecture = "ARM64 / x86_64";
    bitness = "64-bit";
  }

  // Hexdump snippet
  const lines: string[] = [];
  const limit = Math.min(128, bytes.length);
  for (let i = 0; i < limit; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const hex = Array.from(chunk)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
    const ascii = Array.from(chunk)
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : "."))
      .join("");
    lines.push(`0x${i.toString(16).padStart(4, "0")}  ${hex.padEnd(48, " ")}  |${ascii}|`);
  }

  return {
    format,
    architecture,
    endianness,
    bitness,
    magic: magicHex,
    details,
    hexdump: lines.join("\n"),
  };
}

export function disassembleBytes(bytes: Uint8Array, baseAddress = 0x1000): DisasmInsn[] {
  const instructions: DisasmInsn[] = [];
  let idx = 0;
  let currAddr = baseAddress;

  while (idx < bytes.length) {
    const b0 = bytes[idx];
    const b1 = idx + 1 < bytes.length ? bytes[idx + 1] : 0;
    const b2 = idx + 2 < bytes.length ? bytes[idx + 2] : 0;
    const b3 = idx + 3 < bytes.length ? bytes[idx + 3] : 0;
    const b4 = idx + 4 < bytes.length ? bytes[idx + 4] : 0;

    const hexAddr = `0x${currAddr.toString(16).padStart(4, "0")}`;

    // Standard x86_64 instruction decoding
    if (b0 === 0x90) {
      instructions.push({ address: hexAddr, bytes: "90", mnemonic: "nop", op_str: "" });
      idx += 1;
      currAddr += 1;
    } else if (b0 === 0xc3) {
      instructions.push({ address: hexAddr, bytes: "c3", mnemonic: "ret", op_str: "" });
      idx += 1;
      currAddr += 1;
    } else if (b0 === 0xcc) {
      instructions.push({ address: hexAddr, bytes: "cc", mnemonic: "int3", op_str: "(breakpoint)" });
      idx += 1;
      currAddr += 1;
    } else if (b0 === 0x55) {
      instructions.push({ address: hexAddr, bytes: "55", mnemonic: "push", op_str: "rbp" });
      idx += 1;
      currAddr += 1;
    } else if (b0 === 0x5d) {
      instructions.push({ address: hexAddr, bytes: "5d", mnemonic: "pop", op_str: "rbp" });
      idx += 1;
      currAddr += 1;
    } else if (b0 === 0x48 && b1 === 0x89 && b2 === 0xe5) {
      instructions.push({ address: hexAddr, bytes: "48 89 e5", mnemonic: "mov", op_str: "rbp, rsp" });
      idx += 3;
      currAddr += 3;
    } else if (b0 === 0x48 && b1 === 0x83 && b2 === 0xec) {
      instructions.push({ address: hexAddr, bytes: `48 83 ec ${b3.toString(16).padStart(2, "0")}`, mnemonic: "sub", op_str: `rsp, 0x${b3.toString(16)}` });
      idx += 4;
      currAddr += 4;
    } else if (b0 === 0x48 && b1 === 0x83 && b2 === 0xc4) {
      instructions.push({ address: hexAddr, bytes: `48 83 c4 ${b3.toString(16).padStart(2, "0")}`, mnemonic: "add", op_str: `rsp, 0x${b3.toString(16)}` });
      idx += 4;
      currAddr += 4;
    } else if (b0 === 0x31 && b1 === 0xc0) {
      instructions.push({ address: hexAddr, bytes: "31 c0", mnemonic: "xor", op_str: "eax, eax" });
      idx += 2;
      currAddr += 2;
    } else if (b0 === 0xb8 && idx + 4 < bytes.length) {
      const imm = b1 | (b2 << 8) | (b3 << 16) | (b4 << 24);
      instructions.push({
        address: hexAddr,
        bytes: `b8 ${b1.toString(16).padStart(2, "0")} ${b2.toString(16).padStart(2, "0")} ${b3.toString(16).padStart(2, "0")} ${b4.toString(16).padStart(2, "0")}`,
        mnemonic: "mov",
        op_str: `eax, 0x${imm.toString(16)}`,
      });
      idx += 5;
      currAddr += 5;
    } else if (b0 === 0x0f && b1 === 0x05) {
      instructions.push({ address: hexAddr, bytes: "0f 05", mnemonic: "syscall", op_str: "" });
      idx += 2;
      currAddr += 2;
    } else if (b0 === 0xe8 && idx + 4 < bytes.length) {
      const rel = b1 | (b2 << 8) | (b3 << 16) | (b4 << 24);
      const target = (currAddr + 5 + rel) >>> 0;
      instructions.push({
        address: hexAddr,
        bytes: `e8 ${b1.toString(16).padStart(2, "0")} ${b2.toString(16).padStart(2, "0")} ${b3.toString(16).padStart(2, "0")} ${b4.toString(16).padStart(2, "0")}`,
        mnemonic: "call",
        op_str: `0x${target.toString(16)}`,
      });
      idx += 5;
      currAddr += 5;
    } else if (b0 === 0xeb && idx + 1 < bytes.length) {
      const offset = (b1 << 24) >> 24; // signed
      const target = currAddr + 2 + offset;
      instructions.push({ address: hexAddr, bytes: `eb ${b1.toString(16).padStart(2, "0")}`, mnemonic: "jmp", op_str: `0x${target.toString(16)}` });
      idx += 2;
      currAddr += 2;
    } else if (b0 === 0x74 && idx + 1 < bytes.length) {
      const offset = (b1 << 24) >> 24;
      const target = currAddr + 2 + offset;
      instructions.push({ address: hexAddr, bytes: `74 ${b1.toString(16).padStart(2, "0")}`, mnemonic: "je", op_str: `0x${target.toString(16)}` });
      idx += 2;
      currAddr += 2;
    } else if (b0 === 0x75 && idx + 1 < bytes.length) {
      const offset = (b1 << 24) >> 24;
      const target = currAddr + 2 + offset;
      instructions.push({ address: hexAddr, bytes: `75 ${b1.toString(16).padStart(2, "0")}`, mnemonic: "jne", op_str: `0x${target.toString(16)}` });
      idx += 2;
      currAddr += 2;
    } else {
      instructions.push({ address: hexAddr, bytes: b0.toString(16).padStart(2, "0"), mnemonic: "db", op_str: `0x${b0.toString(16).padStart(2, "0")}` });
      idx += 1;
      currAddr += 1;
    }
  }

  return instructions;
}

export function extractStrings(bytes: Uint8Array, minLen = 4): {
  strings: string[];
  urls: string[];
  ips: string[];
  secrets: string[];
} {
  const strings: string[] = [];
  let current: number[] = [];

  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b >= 32 && b <= 126) {
      current.push(b);
    } else {
      if (current.length >= minLen) {
        strings.push(String.fromCharCode(...current));
      }
      current = [];
    }
  }
  if (current.length >= minLen) {
    strings.push(String.fromCharCode(...current));
  }

  const urls = strings.filter((s) => s.startsWith("http://") || s.startsWith("https://") || s.includes("://"));
  const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
  const ips = strings.filter((s) => ipRegex.test(s));
  const secretKeywords = ["token", "secret", "password", "key", "admin", "bearer", "private"];
  const secrets = strings.filter((s) => secretKeywords.some((k) => s.toLowerCase().includes(k)));

  return { strings, urls, ips, secrets };
}
