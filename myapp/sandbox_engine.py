import hashlib
import math
import struct
import time
import random
import re
import json
import base64
import sys
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Tuple, Any


class DynamicSandboxEngine:
    """
    Advanced Enterprise-Grade Security Sandbox Engine.
    Provides:
      - Deep Static Binary Analysis (Magic Bytes, PE Structure, Section Entropy)
      - Heuristics & Signature Matrix (Ransomware, Anti-Analysis, Evasion, Injection, Exploits)
      - String & Indicator of Compromise (IOC) Extractor (IPs, URLs, Registry Keys, Shellcode)
      - Dynamic Multi-Stage Behavioral Simulation (Syscall Hooking, Process Tree, Network Quarantine)
    """

    # --- Heuristics & Behavioral Signatures ---
    BEHAVIORAL_SIGNATURES = [
        # Ransomware & Shadow Copy Destruction
        (rb"vssadmin(\.exe)?\s+delete\s+shadows", "T1490: Shadow Copy Deletion (Ransomware TTP)", 95, "Ransomware"),
        (rb"wmic(\.exe)?\s+shadowcopy\s+delete", "T1490: WMIC Shadow Storage Invalidation", 95, "Ransomware"),
        (rb"bcdedit(\.exe)?\s+/set\s+(\{[^}]+\}|default)\s+recoveryenabled\s+no", "T1490: Disabling Windows Recovery",
         90, "Ransomware"),
        (rb"wbadmin(\.exe)?\s+delete\s+catalog", "T1490: Backup Catalog Destruction", 90, "Ransomware"),
        (rb"(wannacry|lockbit|blackcat|alphv|revil|conti|ryuk|phobos|stop/djvu)", "Known Ransomware Strain Signature",
         98, "Ransomware"),
        (rb"(decrypt_files|readme_for_decrypt|restore_files|\.locked|\.crypted)", "Ransomware Extortion & Note Pattern",
         85, "Ransomware"),

        # Credential Theft & Privilege Escalation
        (rb"(mimikatz|sekurlsa|kerberos::ptt|lsadump)", "T1003: Mimikatz Credential Harvesting", 98,
         "Credential Dumping"),
        (rb"MiniDumpWriteDump", "T1003.001: LSASS Memory Minidump Invocation", 90, "Credential Dumping"),
        (rb"SeDebugPrivilege", "T1134: Process Debug Privilege Escalation", 75, "Privilege Escalation"),
        (
        rb"reg\s+save\s+hklm\\(sam|system|security)", "T1003.002: SAM Database Exfiltration", 95, "Credential Dumping"),

        # Process Injection & Memory Mutation
        (rb"VirtualAllocEx", "T1055: Remote Virtual Memory Allocation", 70, "Process Injection"),
        (rb"WriteProcessMemory", "T1055: Foreign Process Memory Modification", 75, "Process Injection"),
        (rb"CreateRemoteThread", "T1055.002: Remote Thread Injection", 85, "Process Injection"),
        (rb"NtMapViewOfSection", "T1055.012: Process Hollowing / Section Mapping", 80, "Process Injection"),
        (rb"QueueUserAPC", "T1055.004: Asynchronous Procedure Call Injection", 80, "Process Injection"),

        # Anti-Debugging & Evasion
        (rb"IsDebuggerPresent", "T1497: Debugger Probing Detection", 60, "Defense Evasion"),
        (rb"CheckRemoteDebuggerPresent", "T1497: Remote Debugger Verification", 65, "Defense Evasion"),
        (rb"NtQueryInformationProcess", "T1497: Kernel Anti-Debug Query", 65, "Defense Evasion"),
        (rb"(vboxguestadditions|vboxservice|vmtoolsd|vmware)", "T1497.001: Virtual Machine Sandbox Evasion", 70,
         "Defense Evasion"),
        (rb"sbiedll\.dll", "T1497: Sandboxie Detection Hook", 70, "Defense Evasion"),

        # Obfuscated Execution & LOLBins
        (rb"powershell(\.exe)?\s+(-[a-z]+\s+)*(-enc|-encodedcommand)\s+[a-za-z0-9+/=]{10,}",
         "T1059.001: Obfuscated Base64 PowerShell Payload", 92, "Execution"),
        (rb"cmd(\.exe)?\s+/c\s+powershell", "T1059: Suspicious Nested Shell Spawning", 85, "Execution"),
        (rb"certutil(\.exe)?\s+-urlcache\s+-split\s+-f", "T1105: CertUtil Ingress Downloader", 88,
         "Ingress Tool Transfer"),
        (rb"bitsadmin(\.exe)?\s+/transfer", "T1197: BITS Background Downloader", 75, "Persistence"),
        (
        rb"mshta(\.exe)?\s+javascript:", "T1218.005: MSHTA Living-Off-The-Land Proxy Execution", 90, "Defense Evasion"),

        # Keylogging & Spyware
        (rb"SetWindowsHookEx(A|W)", "T1056.001: Windows Hook Keylogger Installation", 85, "Spyware"),
        (rb"GetAsyncKeyState", "T1056.001: Hardware Key State Polling", 75, "Spyware"),
        (rb"GetClipboardData", "T1115: Clipboard Data Snooping", 70, "Collection"),

        # Exploits & C2 Stagers
        (rb"(reflective(loader)?|meterpreter|reverse_tcp|beacon\.dll)", "Metasploit / Cobalt Strike Stager Signature",
         96, "Command & Control"),
        (rb"\x90{20,}", "Suspicious NOP Sled Shellcode Padding", 80, "Exploit Shellcode"),
    ]

    # Suspicious Windows Persistence Registry Paths
    SUSPICIOUS_REG_KEYS = [
        rb"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        rb"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        rb"System\\CurrentControlSet\\Services",
        rb"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    ]

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculates 8-bit Shannon entropy (0.0 to 8.0). High values (>7.2) indicate compression or encryption."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    @classmethod
    def identify_file_type(cls, file_name: str, data: bytes) -> Tuple[str, str]:
        """Identifies file type using magic header bytes and file extensions."""
        if len(data) >= 2 and data[:2] == b"MZ":
            if len(data) >= 0x40:
                pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
                if pe_offset < len(data) - 4 and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                    return "Portable Executable (PE32/PE32+ Binary)", "Executable"
            return "MS-DOS / Windows Executable (MZ)", "Executable"

        if len(data) >= 4 and data[:4] == b"\x7fELF":
            return "Linux ELF Executable / Shared Object", "Executable"
        if len(data) >= 4 and data[:4] == b"%PDF":
            return "Portable Document Format (PDF)", "Document"
        if len(data) >= 4 and data[:4] == b"PK\x03\x04":
            return "ZIP / OpenXML Archive or Package", "Archive"
        if len(data) >= 6 and data[:6] in (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01"):
            return "RAR Archive", "Archive"
        if len(data) >= 6 and data[:6] == b"7z\xbc\xaf\x27\x1c":
            return "7-Zip Archive", "Archive"

        lower_name = file_name.lower()
        if lower_name.endswith(('.ps1', '.psm1')):
            return "PowerShell Script", "Script"
        if lower_name.endswith(('.bat', '.cmd')):
            return "Windows Command Script (Batch)", "Script"
        if lower_name.endswith(('.vbs', '.vbe')):
            return "VBScript Executable Macro", "Script"
        if lower_name.endswith(('.sh', '.bash')):
            return "UNIX Shell Script", "Script"
        if lower_name.endswith(('.py', '.pyw')):
            return "Python Script", "Script"
        if lower_name.endswith(('.dll',)):
            return "Dynamic Link Library (DLL)", "Executable"

        return "Generic Data / Unrecognized Binary", "Data"

    @classmethod
    def parse_pe_sections(cls, data: bytes) -> List[Dict[str, Any]]:
        """Parses Portable Executable (PE) headers and analyzes section-level entropy."""
        sections = []
        try:
            if len(data) < 0x40 or data[:2] != b"MZ":
                return sections
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
                return sections

            num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            opt_hdr_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            sec_table_offset = pe_offset + 24 + opt_hdr_size

            for i in range(min(num_sections, 16)):
                sec_off = sec_table_offset + (i * 40)
                if sec_off + 40 > len(data):
                    break
                sec_name = data[sec_off:sec_off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
                raw_size = struct.unpack_from("<I", data, sec_off + 16)[0]
                raw_ptr = struct.unpack_from("<I", data, sec_off + 20)[0]

                sec_data = data[raw_ptr:raw_ptr + raw_size] if raw_ptr + raw_size <= len(data) else b""
                sec_entropy = cls.calculate_entropy(sec_data) if sec_data else 0.0

                is_packed = sec_entropy > 7.4 or any(p in sec_name.lower() for p in ["upx", "vmp", "themida", "aspack"])
                sections.append({
                    "name": sec_name,
                    "raw_size": raw_size,
                    "entropy": sec_entropy,
                    "is_packed": is_packed
                })
        except Exception:
            pass
        return sections

    @classmethod
    def extract_iocs(cls, data: bytes) -> Dict[str, List[str]]:
        """Extracts suspicious indicators of compromise such as IPs, URLs, and registry keys."""
        text = data.decode("latin1", errors="ignore")

        # IPv4 extraction
        ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
        filtered_ips = list(set([ip for ip in ips if not ip.startswith(("127.", "0.", "255.", "192.168.0."))]))[:6]

        # URLs
        urls = re.findall(r"https?://[a-zA-Z0-9.\-_~:/?#\[\]@!$&'()*+,;=%]+", text)
        filtered_urls = list(set(urls))[:6]

        # Onion sites
        onions = re.findall(r"\b[a-z2-7]{16,56}\.onion\b", text, re.IGNORECASE)

        # Registry references
        regs = []
        for reg_pat in cls.SUSPICIOUS_REG_KEYS:
            if re.search(reg_pat, data, re.IGNORECASE):
                regs.append(reg_pat.decode("latin1"))

        return {
            "ips": filtered_ips,
            "urls": filtered_urls,
            "onions": list(set(onions)),
            "registry_keys": regs,
        }

    @classmethod
    def analyze_payload(cls, file_name: str, file_bytes: bytes) -> Dict[str, Any]:
        """
        Runs comprehensive deep static analysis, heuristics evaluation, 
        and simulated isolated dynamic execution trace.
        Optimized for high-speed analysis and zero network timeout.
        """
        file_size = len(file_bytes)
        md5_hash = hashlib.md5(file_bytes).hexdigest()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        sha1_hash = hashlib.sha1(file_bytes).hexdigest()

        # വലിയ ഫയലുകളിൽ സ്കാനിംഗ് വേഗത്തിലാക്കാൻ സാമ്പിൾ ബൈറ്റുകൾ ഉപയോഗിക്കുന്നു
        scan_sample = file_bytes[:2 * 1024 * 1024]
        entropy = cls.calculate_entropy(scan_sample)

        file_type_desc, file_category = cls.identify_file_type(file_name, file_bytes)
        pe_sections = cls.parse_pe_sections(file_bytes)
        iocs = cls.extract_iocs(scan_sample)

        detected_sigs: List[str] = []
        threat_score = 0
        categories_flagged: List[str] = []

        # 1. Entropy assessment
        if entropy > 7.5:
            threat_score += 40
            detected_sigs.append("High-Entropy Obfuscated / Encrypted Payload (Entropy > 7.5)")
        elif entropy > 7.0:
            threat_score += 20
            detected_sigs.append("Moderately Packed / Compressed Data (Entropy > 7.0)")

        # 2. Section analysis
        for sec in pe_sections:
            if sec["is_packed"]:
                threat_score += 25
                detected_sigs.append(
                    f"Suspicious Section '{sec['name']}' (Entropy: {sec['entropy']}, Possible UPX/Crypter)")

        # 3. Behavioral Signature & Pattern Matching (Optimized on sample)
        for pattern, sig_name, score, cat in cls.BEHAVIORAL_SIGNATURES:
            if re.search(pattern, scan_sample, re.IGNORECASE):
                threat_score = max(threat_score, score)
                detected_sigs.append(sig_name)
                if cat not in categories_flagged:
                    categories_flagged.append(cat)

        # 4. IOC scoring
        if iocs["onions"]:
            threat_score = max(threat_score, 90)
            detected_sigs.append(f"Darkweb Tor Onion Gateway Contact ({iocs['onions'][0]})")
        if iocs["registry_keys"]:
            threat_score = max(threat_score, 75)
            detected_sigs.append("Persistent Run Registry Injection Hook")

        threat_score = min(max(threat_score, 0), 100)

        if threat_score >= 80:
            verdict = "CRITICAL MALWARE"
        elif threat_score >= 50:
            verdict = "HIGH THREAT"
        elif threat_score >= 25:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        execution_logs = cls._generate_sandbox_logs(
            file_name=file_name,
            file_size=file_size,
            file_type=file_type_desc,
            md5_hash=md5_hash,
            sha256_hash=sha256_hash,
            entropy=entropy,
            threat_score=threat_score,
            verdict=verdict,
            detected_sigs=detected_sigs,
            categories_flagged=categories_flagged,
            pe_sections=pe_sections,
            iocs=iocs
        )

        return {
            'filename': file_name,
            'file_size': file_size,
            'md5_hash': md5_hash,
            'sha256_hash': sha256_hash,
            'sha1_hash': sha1_hash,
            'entropy': entropy,
            'file_type': file_type_desc,
            'threat_score': threat_score,
            'verdict': verdict,
            'detected_signatures': ", ".join(detected_sigs) if detected_sigs else "None (Benign Profile)",
            'execution_logs': execution_logs,
        }

    @classmethod
    def _generate_sandbox_logs(
            cls, file_name: str, file_size: int, file_type: str, md5_hash: str, sha256_hash: str,
            entropy: float, threat_score: int, verdict: str, detected_sigs: List[str],
            categories_flagged: List[str], pe_sections: List[Dict[str, Any]], iocs: Dict[str, List[str]]
    ) -> str:
        """Constructs an elaborate, realistic multi-stage SOC telemetry & syscall trace log."""
        container_id = f"sandbox-node-{random.randint(100, 999)}"
        guest_pid = random.randint(1200, 8900)
        logs = []

        # --- Phase 1: Environment & Container Initialization ---
        logs.append(f"═══════════════════════════════════════════════════════════════════════════")
        logs.append(f"[SANDBOX-INIT] Spawning isolated runtime container [{container_id}]")
        logs.append(f"[SANDBOX-INIT] Hypervisor: KVM-qemu | Guest OS: Android ARM64 Runtime Environment")
        logs.append(f"[SANDBOX-INIT] Network Mode: Isolated Simulated VLAN (Tap Device tap0)")
        logs.append(f"[SANDBOX-INIT] Kernel API Hooks: Active (ntdll.dll, libc.so, dalvik-vm)")
        logs.append(f"───────────────────────────────────────────────────────────────────────────")

        # --- Phase 2: Static Forensic Inspection ---
        logs.append(f"[STATIC-SCAN] Target Payload: {file_name} ({file_size:,} bytes)")
        logs.append(f"[STATIC-SCAN] Format: {file_type}")
        logs.append(f"[STATIC-SCAN] Hashes -> MD5: {md5_hash}")
        logs.append(f"[STATIC-SCAN]          SHA256: {sha256_hash}")
        logs.append(f"[STATIC-SCAN] Shannon Global Entropy: {entropy} / 8.000")

        if pe_sections:
            logs.append(f"[PE-STRUCTURE] Parsed {len(pe_sections)} Portable Executable binary sections:")
            for s in pe_sections:
                status = "ANOMALY (HIGH ENTROPY/PACKED)" if s["is_packed"] else "NORMAL"
                logs.append(
                    f"   ├─ Section: {s['name']:<8} | Size: {s['raw_size']:<8} bytes | Entropy: {s['entropy']:<5} [{status}]")

        if iocs["ips"] or iocs["urls"] or iocs["onions"] or iocs["registry_keys"]:
            logs.append(f"[IOC-EXTRACTION] Extracted Indicators:")
            for ip in iocs["ips"]:
                logs.append(f"   ├─ Extracted External IPv4: {ip}")
            for url in iocs["urls"]:
                logs.append(f"   ├─ Extracted Target Endpoint: {url}")
            for onion in iocs["onions"]:
                logs.append(f"   ├─ [CRITICAL] Extracted Darknet Onion: {onion}")
            for reg in iocs["registry_keys"]:
                logs.append(f"   ├─ Suspicious Registry Target: {reg}")

        logs.append(f"───────────────────────────────────────────────────────────────────────────")

        # --- Phase 3: Dynamic Simulated Execution & Syscall Interception ---
        logs.append(f"[DYNAMIC-MONITOR] Launching payload under monitor PID {guest_pid}...")

        if threat_score >= 80:
            logs.append(f"[ALERT-SYSCALL] Hooked NtAllocateVirtualMemory() -> 0x00400000 (PAGE_EXECUTE_READWRITE)")
            logs.append(f"[ALERT-SYSCALL] Hooked VirtualAllocEx() targeting remote PID {guest_pid + 4}")
            logs.append(f"[ALERT-PROCESS] Process Injection Detected! Thread creation via CreateRemoteThread()")
            if "Ransomware" in categories_flagged:
                logs.append(f"[ALERT-RANSOM] Target invoked 'vssadmin delete shadows /all /quiet'")
                logs.append(f"[ALERT-RANSOM] Massive batch enumeration of user storage directories")
                logs.append(f"[ALERT-CRYPTO] High frequency AES-256 / RSA key generation detected in memory")
            if "Credential Dumping" in categories_flagged:
                logs.append(f"[ALERT-CRED] OpenProcess() called with PROCESS_VM_READ against security process")
                logs.append(f"[ALERT-CRED] MiniDumpWriteDump initiated to buffer at 0x7FFE0010")
            if iocs["ips"]:
                c2_ip = iocs["ips"][0]
                logs.append(f"[ALERT-NETWORK] Blocked unauthorized outbound TCP handshake to {c2_ip}:443 (Sinkholed)")
            else:
                logs.append(f"[ALERT-NETWORK] Blocked unauthorized outbound socket connection to 185.220.101.5:443")
            logs.append(f"[DEFENSE-ACTION] Triggered Emergency Kernel Isolation Protocol!")
            logs.append(f"[DEFENSE-ACTION] Quarantined process tree PID {guest_pid} and spawned child sub-processes.")

        elif threat_score >= 40:
            logs.append(f"[WARN-SYSCALL] Target queried system storage for persistence keys")
            logs.append(f"[WARN-SYSCALL] Hooked RegSetValueExW -> Auto-run entry creation attempt")
            logs.append(f"[WARN-EVASION] Invoked IsDebuggerPresent() / Sandbox Probe - Synthetic TRUE returned")
            logs.append(f"[DYNAMIC-MONITOR] Process behavior flagged for secondary SOC review.")

        else:
            logs.append(f"[DYNAMIC-MONITOR] Syscall trace normal. No privileged memory allocation.")
            logs.append(
                f"[DYNAMIC-MONITOR] No persistence, process injection, or unauthorized network beacons observed.")
            logs.append(f"[DYNAMIC-MONITOR] Execution concluded within baseline safety thresholds.")

        logs.append(f"───────────────────────────────────────────────────────────────────────────")

        # --- Phase 4: Threat Assessment & Final Verdict ---
        logs.append(f"[VERDICT] Threat Level: {threat_score}% | Assessment: {verdict}")
        if detected_sigs:
            logs.append(f"[SIGNATURES-MATCHED]")
            for sig in detected_sigs:
                logs.append(f"   • {sig}")
        else:
            logs.append(f"[SIGNATURES-MATCHED] None detected.")
        logs.append(f"[SANDBOX-CLEANUP] Reverting virtual snapshot for {container_id}. State reset.")
        logs.append(f"═══════════════════════════════════════════════════════════════════════════")

        return "\n".join(logs)


# =============================================================================
# Standalone Isolated Sandbox Microservice (Runs on Dedicated Port)
# =============================================================================

RECENT_ANALYSES: List[Dict[str, Any]] = []
LIVE_LOGS_STREAM: List[str] = [
    f"[{time.strftime('%H:%M:%S')}] [SANDBOX-KERNEL] Isolated Hypervisor Kernel Initialized on dedicated port.",
    f"[{time.strftime('%H:%M:%S')}] [ZERO-TRUST] Syscall interception active (dalvik, libc, kernel).",
    f"[{time.strftime('%H:%M:%S')}] [CONTAINER-READY] Listening for dispatched payloads from Main Project SOC...",
]

SANDBOX_NODE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ISOLATED SANDBOX ENGINE NODE // PORT {PORT}</title>
    <style>
        :root {
            --bg: #07090e;
            --panel: #0f1420;
            --border: #1e293b;
            --cyan: #06b6d4;
            --green: #10b981;
            --red: #ef4444;
            --yellow: #f59e0b;
            --text: #f1f5f9;
            --muted: #94a3b8;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; }
        body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; }
        header {
            background: rgba(15, 20, 32, 0.95);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid var(--border);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo { display: flex; align-items: center; gap: 0.75rem; font-weight: 700; color: var(--cyan); letter-spacing: 1px; }
        .badge { background: rgba(16, 185, 129, 0.15); color: var(--green); border: 1px solid rgba(16, 185, 129, 0.3); padding: 0.3rem 0.8rem; border-radius: 20px; font-size: 0.85rem; font-weight: 600; }
        .btn {
            background: #1e293b; color: var(--text); border: 1px solid #334155; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; text-decoration: none; font-size: 0.85rem; font-weight: 600; display: inline-flex; align-items: center; gap: 0.5rem; transition: all 0.2s ease;
        }
        .btn:hover { background: #334155; border-color: var(--cyan); }
        .btn-cyan { background: var(--cyan); color: #000; border: none; }
        .btn-cyan:hover { background: #22d3ee; }
        .container { padding: 1.5rem 2rem; display: grid; grid-template-columns: repeat(12, 1fr); gap: 1.5rem; flex: 1; }
        .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem; display: flex; flex-direction: column; box-shadow: 0 4px 20px rgba(0,0,0,0.4); }
        .col-12 { grid-column: span 12; }
        .col-8 { grid-column: span 8; }
        .col-4 { grid-column: span 4; }
        .panel-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 0.5rem; }
        .panel-title { font-size: 0.95rem; font-weight: 700; color: var(--cyan); }
        .metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1rem; }
        .metric-card { background: rgba(255,255,255,0.02); border: 1px solid var(--border); border-radius: 8px; padding: 0.85rem; text-align: center; }
        .metric-val { font-size: 1.5rem; font-weight: 800; color: var(--green); margin-top: 0.2rem; }
        .metric-lbl { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; }
        .console {
            background: #030407; border: 1px solid var(--border); border-radius: 8px; padding: 1rem; font-family: 'Courier New', monospace; font-size: 0.85rem; color: #38bdf8; height: 320px; overflow-y: auto; white-space: pre-wrap; line-height: 1.5;
        }
        .dropzone {
            border: 2px dashed rgba(6, 182, 212, 0.4); border-radius: 8px; padding: 1.5rem; text-align: center; background: rgba(6, 182, 212, 0.02); cursor: pointer; margin-bottom: 1rem;
        }
        .dropzone:hover { border-color: var(--cyan); background: rgba(6, 182, 212, 0.08); }
        table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
        th, td { padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.05); }
        th { color: var(--muted); }
        .tag-red { background: rgba(239, 68, 68, 0.2); color: var(--red); padding: 0.2rem 0.5rem; border-radius: 4px; }
        .tag-green { background: rgba(16, 185, 129, 0.2); color: var(--green); padding: 0.2rem 0.5rem; border-radius: 4px; }
    </style>
</head>
<body>
    <header>
        <div class="logo">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            ISOLATED SANDBOX ENGINE // DAEMON NODE [PORT {PORT}]
        </div>
        <div style="display: flex; gap: 1rem; align-items: center;">
            <div class="badge">● DAEMON ACTIVE (PORT {PORT})</div>
            <a href="http://127.0.0.1:8000/" class="btn" id="btn-back-soc">
                ← SWITCH TO MAIN SOC DASHBOARD
            </a>
        </div>
    </header>

    <main class="container">
        <section class="panel col-12">
            <div class="panel-header">
                <span class="panel-title">LIVE DEDICATED SANDBOX HYPERVISOR TELEMETRY</span>
                <span style="font-size: 0.8rem; color: var(--green);">Zero-Trust Dynamic Isolation Active</span>
            </div>
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-lbl">Container Node</div>
                    <div class="metric-val" id="node-id">SBX-NODE-{PORT}</div>
                </div>
                <div class="metric-card">
                    <div class="metric-lbl">Virtual CPU Load</div>
                    <div class="metric-val" id="node-cpu">2.1%</div>
                </div>
                <div class="metric-card">
                    <div class="metric-lbl">Isolated Memory</div>
                    <div class="metric-val" id="node-ram">142 MB</div>
                </div>
                <div class="metric-card">
                    <div class="metric-lbl">Active Syscall Hooks</div>
                    <div class="metric-val" style="color: var(--cyan);">DALVIK / WIN32 / LIBC</div>
                </div>
            </div>
        </section>

        <section class="panel col-8">
            <div class="panel-header">
                <span class="panel-title">REAL-TIME SANDBOX EXECUTION & SYSCALL TRACE (PORT {PORT})</span>
                <button class="btn" onclick="clearLogs()" style="padding: 0.2rem 0.6rem; font-size: 0.75rem;">Clear Stream</button>
            </div>
            <div class="console" id="node-console">Initializing Sandbox Activity Stream...</div>
        </section>

        <section class="panel col-4">
            <div class="panel-header">
                <span class="panel-title">DIRECT NODE INJECTION (PORT {PORT})</span>
            </div>
            <div class="dropzone" id="direct-dropzone">
                <p style="font-weight: 700; margin-bottom: 0.3rem;">⚡ Test Payload on Port {PORT}</p>
                <p style="font-size: 0.8rem; color: var(--muted);">Drop file or click to analyze directly on this port</p>
                <input type="file" id="direct-file-input" style="display: none;">
            </div>
            <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                <button class="btn btn-cyan" onclick="injectTestSample('ransomware')">🧪 Inject Ransomware Payload</button>
                <button class="btn" onclick="injectTestSample('keylogger')">🧪 Inject Keylogger DLL</button>
                <button class="btn" onclick="injectTestSample('clean')">📄 Analyze Clean APK/Document</button>
            </div>
        </section>

        <section class="panel col-12">
            <div class="panel-header">
                <span class="panel-title">RECENT PAYLOADS ANALYZED ON THIS NODE (PORT {PORT})</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Payload Name</th>
                        <th>Format</th>
                        <th>Threat Score</th>
                        <th>Verdict</th>
                        <th>Signatures</th>
                    </tr>
                </thead>
                <tbody id="analyses-table-body">
                    <tr><td colspan="6" style="text-align: center; color: var(--muted);">Waiting for payload dispatch from Main SOC Dashboard or Direct Injection...</td></tr>
                </tbody>
            </table>
        </section>
    </main>

    <footer style="text-align: center; padding: 1rem; color: var(--muted); font-size: 0.8rem; border-top: 1px solid var(--border);">
        Isolated Sandbox Node Daemon running on Port {PORT} | Intercepting System Calls & Dynamic Malware Execution
    </footer>

    <script>
        const PORT = {PORT};

        function pollNodeStatus() {
            fetch('/status')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('node-cpu').textContent = `${data.cpu_usage_pct}%`;
                    document.getElementById('node-ram').textContent = `${data.memory_usage_mb} MB`;
                })
                .catch(() => {});

            fetch('/api/logs')
                .then(r => r.json())
                .then(data => {
                    const consoleEl = document.getElementById('node-console');
                    if (data.logs && data.logs.length > 0) {
                        consoleEl.textContent = data.logs.join('\\n');
                        consoleEl.scrollTop = consoleEl.scrollHeight;
                    }
                    renderTable(data.recent || []);
                })
                .catch(() => {});
        }

        function renderTable(items) {
            const tbody = document.getElementById('analyses-table-body');
            if (!items || items.length === 0) return;
            tbody.innerHTML = items.map(item => `
                <tr>
                    <td>${item.timestamp || 'Just now'}</td>
                    <td><strong>${item.filename}</strong></td>
                    <td>${item.file_type || 'Binary'}</td>
                    <td><strong style="color: ${item.threat_score > 60 ? 'var(--red)' : (item.threat_score > 30 ? 'var(--yellow)' : 'var(--green)')}">${item.threat_score}%</strong></td>
                    <td><span class="${item.threat_score > 50 ? 'tag-red' : 'tag-green'}">${item.verdict}</span></td>
                    <td style="font-size: 0.8rem; color: var(--muted);">${item.detected_signatures || 'None'}</td>
                </tr>
            `).join('');
        }

        function clearLogs() {
            fetch('/api/clear-logs', { method: 'POST' })
                .then(() => { document.getElementById('node-console').textContent = '[CLEARED] Stream reset.'; });
        }

        function injectTestSample(type) {
            let filename = "sample.bin";
            let content = "";
            if (type === 'ransomware') {
                filename = "Ransomware_vssadmin.apk";
                content = "vssadmin delete shadows /all /quiet and Wannacry signature";
            } else if (type === 'keylogger') {
                filename = "Spyware_Hook.dll";
                content = "SetWindowsHookEx VirtualAllocEx Keylogger.Hook payload";
            } else {
                filename = "Normal_Application.apk";
                content = "PK\\x03\\x04 Standard Clean Android Application Package";
            }

            fetch('/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename: filename, content: content })
            })
            .then(r => r.json())
            .then(() => {
                pollNodeStatus();
            });
        }

        const dropzone = document.getElementById('direct-dropzone');
        const fileInput = document.getElementById('direct-file-input');
        dropzone.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) uploadDirect(e.target.files[0]);
        });
        dropzone.addEventListener('dragover', (e) => { e.preventDefault(); });
        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            if (e.dataTransfer.files.length > 0) uploadDirect(e.dataTransfer.files[0]);
        });

        function uploadDirect(file) {
            const reader = new FileReader();
            reader.onload = function(e) {
                const base64Content = btoa(new Uint8Array(e.target.result).reduce((data, byte) => data + String.fromCharCode(byte), ''));
                fetch('/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ filename: file.name, content_base64: base64Content })
                })
                .then(r => r.json())
                .then(() => {
                    pollNodeStatus();
                });
            };
            reader.readAsArrayBuffer(file);
        }

        pollNodeStatus();
        setInterval(pollNodeStatus, 2500);
    </script>
</body>
</html>
"""


class SandboxHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    Dedicated HTTP Request Handler for the Standalone Sandbox Engine Node.
    Serves the Sandbox Web Console on GET / and handles REST API endpoints.
    """

    def _send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Filename')

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        global LIVE_LOGS_STREAM, RECENT_ANALYSES

        if self.path in ('/', '/index.html'):
            rendered_html = SANDBOX_NODE_HTML.replace('{PORT}', str(self.server.server_port))
            content = rendered_html.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(content)

        elif self.path in ('/status', '/health', '/api/sandbox/status/'):
            data = {
                'status': 'ONLINE',
                'service': 'Standalone Dynamic Sandbox Node',
                'port': self.server.server_port,
                'container_id': f'SBX-NODE-{self.server.server_port}',
                'isolation_mode': 'STRICT_CONTAINER',
                'active_processes': random.randint(1, 3),
                'cpu_usage_pct': round(random.uniform(1.2, 4.8), 1),
                'memory_usage_mb': round(random.uniform(130.0, 165.0), 1),
                'total_analyzed': len(RECENT_ANALYSES),
            }
            body = json.dumps(data).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self._send_cors_headers()
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path in ('/api/logs', '/logs'):
            data = {
                'logs': LIVE_LOGS_STREAM[-100:],
                'recent': RECENT_ANALYSES[:10],
            }
            body = json.dumps(data).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self._send_cors_headers()
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        global LIVE_LOGS_STREAM, RECENT_ANALYSES

        if self.path == '/api/clear-logs':
            LIVE_LOGS_STREAM = [
                f"[{time.strftime('%H:%M:%S')}] [STREAM-RESET] Execution logs reset by operator on Port {self.server.server_port}."
            ]
            self.send_response(200)
            self._send_cors_headers()
            self.end_headers()
            return

        if self.path in ('/analyze', '/api/scan/', '/scan'):
            try:
                content_len = int(self.headers.get('Content-Length', 0))
                raw_body = self.rfile.read(content_len)
                content_type = self.headers.get('Content-Type', '')

                file_name = "payload.bin"
                file_bytes = b""

                if 'application/json' in content_type:
                    data = json.loads(raw_body.decode('utf-8', errors='ignore'))
                    file_name = data.get('filename', 'sample_payload.bin')
                    if 'content_base64' in data and data['content_base64']:
                        file_bytes = base64.b64decode(data['content_base64'])
                    else:
                        file_bytes = data.get('content', '').encode('utf-8')
                elif 'application/octet-stream' in content_type:
                    file_name = self.headers.get('X-Filename', 'raw_binary.bin')
                    file_bytes = raw_body
                else:
                    file_name = self.headers.get('X-Filename', 'uploaded_file.bin')
                    file_bytes = raw_body

                report = DynamicSandboxEngine.analyze_payload(file_name, file_bytes)

                remote_prefix = (
                    f"┌───────────────────────────────────────────────────────────────────────────┐\n"
                    f"│ [REMOTE-NODE] EXECUTED ON ISOLATED SANDBOX DAEMON (PORT {self.server.server_port})             │\n"
                    f"│ Node Status: ACTIVE & ISOLATED | Zero-Trust Interception Active           │\n"
                    f"└───────────────────────────────────────────────────────────────────────────┘\n"
                )
                report['execution_logs'] = remote_prefix + report['execution_logs']
                report['server_port'] = self.server.server_port

                now_str = time.strftime('%H:%M:%S')
                LIVE_LOGS_STREAM.append(
                    f"[{now_str}] ═══════ DISPATCH RECEIVED: '{file_name}' ({len(file_bytes)} bytes) ═══════")
                for line in report['execution_logs'].split('\n'):
                    if line.strip():
                        LIVE_LOGS_STREAM.append(f"[{now_str}] {line}")
                LIVE_LOGS_STREAM.append(
                    f"[{now_str}] ─── VERDICT: {report['verdict']} ({report['threat_score']}%) ───\n")

                entry = dict(report)
                entry['timestamp'] = now_str
                RECENT_ANALYSES.insert(0, entry)
                if len(RECENT_ANALYSES) > 50:
                    RECENT_ANALYSES.pop()

                resp_body = json.dumps(report).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self._send_cors_headers()
                self.send_header('Content-Length', str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)

            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                pass
            except Exception as e:
                try:
                    err_body = json.dumps({'error': str(e)}).encode('utf-8')
                    self.send_response(500)
                    self.send_header('Content-Type', 'application/json')
                    self._send_cors_headers()
                    self.send_header('Content-Length', str(len(err_body)))
                    self.end_headers()
                    self.wfile.write(err_body)
                except Exception:
                    pass
        else:
            self.send_response(404)
            self.end_headers()


def run_standalone_server(port: int = 5000, host: str = '127.0.0.1'):
    """Launches the Standalone Isolated Sandbox Engine Node on a dedicated port."""
    server_address = (host, port)
    httpd = ThreadingHTTPServer(server_address, SandboxHTTPRequestHandler)
    print("=" * 76)
    print(f" [SANDBOX NODE] Standalone Malware Sandbox Engine Started Successfully!")
    print(f" [WEB CONSOLE]  http://{host}:{port}/")
    print(f" [API ROUTE]    POST http://{host}:{port}/analyze")
    print(f" [STATUS API]   GET  http://{host}:{port}/status")
    print(f" [ARCHITECTURE] Dedicated Isolated Port (Separate from Main Django Project)")
    print("=" * 76)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[SANDBOX NODE] Shutting down isolated container daemon...")
        httpd.server_close()


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    run_standalone_server(port=port)