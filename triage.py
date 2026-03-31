#!/usr/bin/env python3
"""
Go Binary Triage Toolkit
Companion to GoReSym (https://github.com/mandiant/GoReSym)

Usage:
    python triage.py sample_output.json
    python triage.py sample_output.json --json
"""

import json
import re
import sys
import argparse
from dataclasses import dataclass, field
from typing import Optional

# ── ANSI colour helpers ────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
DIM    = "\033[2m"

def bold(s):   return f"{BOLD}{s}{RESET}"
def red(s):    return f"{RED}{s}{RESET}"
def yellow(s): return f"{YELLOW}{s}{RESET}"
def green(s):  return f"{GREEN}{s}{RESET}"
def cyan(s):   return f"{CYAN}{s}{RESET}"
def dim(s):    return f"{DIM}{s}{RESET}"

# ── Detection patterns ─────────────────────────────────────────────────────────

URL_RE = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
IP_RE  = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b')
PRIV_IP_RE = re.compile(
    r'\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|127\.\d+\.\d+\.\d+)\b'
)

SHELL_COMMANDS = {
    "cmd.exe", "powershell", "powershell.exe", "bash", "/bin/sh", "/bin/bash",
    "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil",
}

FUNC_CATEGORIES = [
    ("network",       ["net/http", "net/dial", "net/tcp", "net/udp",
                       "net.Dial", "net.Listen", "http.Get", "http.Post"]),
    ("crypto",        ["crypto/aes", "crypto/des", "crypto/rc4", "crypto/rsa",
                       "crypto/cipher", "crypto/hmac", "crypto/md5", "crypto/sha"]),
    ("execution",     ["os/exec", "syscall.Exec", "syscall.ForkExec",
                       "exec.Command", "exec.Run", "exec.Start"]),
    ("filesystem",    ["os.Open", "os.Create", "os.Remove", "os.Rename",
                       "os.ReadFile", "os.WriteFile", "ioutil.ReadFile"]),
    ("persistence",   ["registry", "startup", "autorun", "schtask",
                       "cron", "launchd", "systemd"]),
    ("anti_analysis", ["ptrace", "debugger", "isdebugged", "obfuscat",
                       "virtualbox", "vmware", "sandbox"]),
]

# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class SuspiciousString:
    value: str
    reason: str  # "url" | "ip" | "ip_private" | "shell_cmd"

@dataclass
class FunctionGroup:
    category: str
    count: int
    examples: list[str] = field(default_factory=list)

@dataclass
class TriageReport:
    go_version:         str
    arch:               str
    build_id:           str
    os:                 Optional[str]
    suspicious_strings: list[SuspiciousString]
    function_groups:    list[FunctionGroup]
    capabilities:       list[str]
    summary:            str
    risk_score:         int
    risk_label:         str

# ── Phase 1: Load and parse GoReSym JSON ──────────────────────────────────────

def load_goresym(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def extract_metadata(data: dict) -> tuple[str, str, str, Optional[str]]:
    version  = data.get("Version", "unknown")
    build_id = data.get("BuildId", "")
    arch     = data.get("Arch", "unknown")
    os_info  = data.get("Os") or data.get("os")
    if not os_info:
        os_info = data.get("TabMeta", {}).get("Os")
    return version, arch, build_id, os_info

# ── Phase 2: Suspicious string detection ─────────────────────────────────────

def detect_suspicious_strings(data: dict) -> list[SuspiciousString]:
    raw_strings = data.get("Strings", [])
    results: list[SuspiciousString] = []
    seen: set[str] = set()

    def _check(s: str):
        if not s or s in seen:
            return
        seen.add(s)

        if URL_RE.search(s):
            results.append(SuspiciousString(value=s, reason="url"))
            return

        ip_match = IP_RE.search(s)
        if ip_match:
            ip = ip_match.group()
            if not PRIV_IP_RE.match(ip):
                results.append(SuspiciousString(value=s, reason="ip"))
                return
            if len(s.strip()) < 20:
                results.append(SuspiciousString(value=s, reason="ip_private"))
                return

        s_lower = s.lower()
        for cmd in SHELL_COMMANDS:
            if cmd in s_lower:
                results.append(SuspiciousString(value=s, reason="shell_cmd"))
                return

    for entry in raw_strings:
        if isinstance(entry, str):
            _check(entry)
        elif isinstance(entry, dict):
            _check(entry.get("str", "") or entry.get("String", ""))

    return results

# ── Phase 3: Function classification ─────────────────────────────────────────

def classify_functions(data: dict) -> list[FunctionGroup]:
    all_funcs: list[str] = []

    for key in ("UserFunctions", "StdFunctions"):
        for fn in data.get(key, []):
            name = fn.get("FullName") or fn.get("Name") or "" if isinstance(fn, dict) else str(fn)
            if name:
                all_funcs.append(name)

    groups: list[FunctionGroup] = []
    for category, patterns in FUNC_CATEGORIES:
        matched = [
            name for name in all_funcs
            if any(p.lower() in name.lower() for p in patterns)
        ]
        if matched:
            unique = list(dict.fromkeys(matched))
            groups.append(FunctionGroup(
                category=category,
                count=len(unique),
                examples=unique[:5],
            ))
    return groups

# ── Phase 4: Capability inference ────────────────────────────────────────────

CAPABILITY_MAP = {
    "network":       "Network communication (HTTP/TCP/TLS)",
    "crypto":        "Encryption / cryptographic operations",
    "execution":     "Command or process execution",
    "filesystem":    "File system access (read/write)",
    "persistence":   "Persistence mechanism (registry / scheduled tasks)",
    "anti_analysis": "Anti-analysis / evasion techniques",
}

def infer_capabilities(
    function_groups: list[FunctionGroup],
    suspicious_strings: list[SuspiciousString],
) -> list[str]:
    caps: list[str] = []
    group_names = {g.category for g in function_groups}

    for cat, label in CAPABILITY_MAP.items():
        if cat in group_names:
            caps.append(label)

    reasons = {s.reason for s in suspicious_strings}
    if "url" in reasons and "Network communication (HTTP/TCP/TLS)" not in caps:
        caps.append("Network communication (hardcoded URLs detected)")
    if "ip" in reasons and "Network communication (HTTP/TCP/TLS)" not in caps:
        caps.append("Network communication (hardcoded IPs detected)")
    if "shell_cmd" in reasons and "Command or process execution" not in caps:
        caps.append("Command or process execution (shell strings detected)")

    return caps

# ── Phase 5: Risk scoring ─────────────────────────────────────────────────────

RISK_WEIGHTS = {
    "network":       15,
    "crypto":        15,
    "execution":     25,
    "persistence":   25,
    "anti_analysis": 20,
    "filesystem":    10,
}

STRING_RISK = {
    "url":        10,
    "ip":         10,
    "ip_private":  3,
    "shell_cmd":  15,
}

def compute_risk(
    function_groups: list[FunctionGroup],
    suspicious_strings: list[SuspiciousString],
) -> tuple[int, str]:
    score = 0
    for g in function_groups:
        score += RISK_WEIGHTS.get(g.category, 5)
    for s in suspicious_strings:
        score += STRING_RISK.get(s.reason, 5)

    score = min(score, 100)

    if score >= 75:   label = "CRITICAL"
    elif score >= 50: label = "HIGH"
    elif score >= 25: label = "MEDIUM"
    else:             label = "LOW"

    return score, label

# ── Phase 6: Summary + orchestrator ──────────────────────────────────────────

def generate_summary(
    go_version: str,
    arch: str,
    capabilities: list[str],
    suspicious_strings: list[SuspiciousString],
    risk_label: str,
) -> str:
    parts = [f"Go {go_version} binary ({arch})."]

    if capabilities:
        cap_str = "; ".join(capabilities[:3])
        if len(capabilities) > 3:
            cap_str += f"; and {len(capabilities) - 3} more"
        parts.append(f"Detected capabilities: {cap_str}.")

    url_count = sum(1 for s in suspicious_strings if s.reason == "url")
    ip_count  = sum(1 for s in suspicious_strings if "ip" in s.reason)
    cmd_count = sum(1 for s in suspicious_strings if s.reason == "shell_cmd")

    ioc_parts = []
    if url_count: ioc_parts.append(f"{url_count} suspicious URL(s)")
    if ip_count:  ioc_parts.append(f"{ip_count} hardcoded IP(s)")
    if cmd_count: ioc_parts.append(f"{cmd_count} shell command reference(s)")
    if ioc_parts:
        parts.append("IOC indicators: " + ", ".join(ioc_parts) + ".")

    parts.append(f"Overall risk assessment: {risk_label}.")
    return " ".join(parts)

def run_triage(path: str) -> TriageReport:
    data = load_goresym(path)
    go_version, arch, build_id, os_info = extract_metadata(data)
    suspicious_strings = detect_suspicious_strings(data)
    function_groups    = classify_functions(data)
    capabilities       = infer_capabilities(function_groups, suspicious_strings)
    risk_score, risk_label = compute_risk(function_groups, suspicious_strings)
    summary = generate_summary(go_version, arch, capabilities, suspicious_strings, risk_label)

    return TriageReport(
        go_version=go_version,
        arch=arch,
        build_id=build_id,
        os=os_info,
        suspicious_strings=suspicious_strings,
        function_groups=function_groups,
        capabilities=capabilities,
        summary=summary,
        risk_score=risk_score,
        risk_label=risk_label,
    )

# ── Terminal renderer ─────────────────────────────────────────────────────────

RISK_COLORS = {
    "LOW":      green,
    "MEDIUM":   yellow,
    "HIGH":     red,
    "CRITICAL": lambda s: f"\033[1;91m{s}{RESET}",
}

def _risk_bar(score: int, width: int = 30) -> str:
    filled = int(score / 100 * width)
    return "█" * filled + "░" * (width - filled)

def print_report(report: TriageReport):
    SEP = "─" * 60

    print()
    print(bold("╔══════════════════════════════════════════════════════════╗"))
    print(bold("║         GO BINARY TRIAGE TOOLKIT  (GoReSym companion)   ║"))
    print(bold("╚══════════════════════════════════════════════════════════╝"))

    # ── Metadata ──
    print()
    print(bold("  BINARY METADATA"))
    print(f"  {dim(SEP)}")
    print(f"  Go Version  : {cyan(report.go_version)}")
    print(f"  Architecture: {cyan(report.arch)}")
    if report.os:
        print(f"  OS          : {cyan(report.os)}")
    if report.build_id:
        bid = report.build_id[:48] + "..." if len(report.build_id) > 48 else report.build_id
        print(f"  Build ID    : {dim(bid)}")

    # ── Risk score ──
    print()
    print(bold("  RISK SCORE"))
    print(f"  {dim(SEP)}")
    color_fn = RISK_COLORS.get(report.risk_label, yellow)
    print(f"  {_risk_bar(report.risk_score)}  {color_fn(f'{report.risk_score}/100  [{report.risk_label}]')}")

    # ── Capabilities ──
    print()
    print(bold("  INFERRED CAPABILITIES"))
    print(f"  {dim(SEP)}")
    if report.capabilities:
        for cap in report.capabilities:
            print(f"  {yellow('▸')} {cap}")
    else:
        print(f"  {green('None detected')}")

    # ── Function classification ──
    print()
    print(bold("  FUNCTION BEHAVIOUR CLASSIFICATION"))
    print(f"  {dim(SEP)}")
    if report.function_groups:
        for g in sorted(report.function_groups, key=lambda x: -x.count):
            label = g.category.upper().ljust(14)
            print(f"  {cyan(label)}  {bold(str(g.count))} functions matched")
            for ex in g.examples:
                print(f"    {dim('└─')} {ex}")
    else:
        print(f"  {green('No suspicious function patterns found')}")

    # ── Suspicious strings ──
    print()
    print(bold("  SUSPICIOUS STRINGS / IOCs"))
    print(f"  {dim(SEP)}")
    if report.suspicious_strings:
        by_reason: dict[str, list[str]] = {}
        for s in report.suspicious_strings:
            by_reason.setdefault(s.reason, []).append(s.value)

        reason_labels = {
            "url":        ("URLs",         red),
            "ip":         ("Public IPs",   red),
            "ip_private": ("Private IPs",  yellow),
            "shell_cmd":  ("Shell Commands", red),
        }
        for reason, (label, color_fn) in reason_labels.items():
            entries = by_reason.get(reason, [])
            if not entries:
                continue
            print(f"  {color_fn(label)} ({len(entries)} found):")
            for val in entries[:8]:
                display = val if len(val) <= 80 else val[:77] + "..."
                print(f"    {dim('└─')} {display}")
            if len(entries) > 8:
                print(f"    {dim(f'... and {len(entries) - 8} more')}")
    else:
        print(f"  {green('No suspicious strings detected')}")

    # ── Summary ──
    print()
    print(bold("  ANALYST SUMMARY"))
    print(f"  {dim(SEP)}")
    words = report.summary.split()
    line, lines = "", []
    for w in words:
        if len(line) + len(w) + 1 > 70:
            lines.append(line)
            line = w
        else:
            line = (line + " " + w).strip()
    if line:
        lines.append(line)
    for l in lines:
        print(f"  {l}")

    print()
    print(dim("  " + SEP))
    print()

# ── JSON renderer ─────────────────────────────────────────────────────────────

def print_json_report(report: TriageReport):
    out = {
        "metadata": {
            "go_version": report.go_version,
            "arch":       report.arch,
            "build_id":   report.build_id,
            "os":         report.os,
        },
        "risk": {
            "score": report.risk_score,
            "label": report.risk_label,
        },
        "capabilities":       report.capabilities,
        "function_groups": [
            {"category": g.category, "count": g.count, "examples": g.examples}
            for g in report.function_groups
        ],
        "suspicious_strings": [
            {"value": s.value, "reason": s.reason}
            for s in report.suspicious_strings
        ],
        "summary": report.summary,
    }
    print(json.dumps(out, indent=2))

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Go Binary Triage Toolkit — companion to GoReSym",
        epilog="Example: python triage.py sample_output.json",
    )
    parser.add_argument("json_file", help="GoReSym JSON output file")
    parser.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON instead of terminal report",
    )
    args = parser.parse_args()

    try:
        report = run_triage(args.json_file)
    except FileNotFoundError:
        print(f"Error: file not found: {args.json_file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON — {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print_json_report(report)
    else:
        print_report(report)


if __name__ == "__main__":
    main()