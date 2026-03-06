"""
Network Vulnerability Scanner — CLI
Usage:
    python main.py --target 192.168.1.1 --profile top100
    python main.py --target localhost --profile web
    python main.py --demo   # scans localhost with simulated open ports
"""

import asyncio
import argparse
import json
from dataclasses import asdict
from src.scanner import AsyncPortScanner, PORT_PROFILES


BANNER = r"""
 _   _      _    _____
| \ | | ___| |_ / ____|
|  \| |/ _ \ __|\__ \ ___ __ _ _ __  _ __   ___ _ __
| |\  |  __/ |_ ___) / __/ _` | '_ \| '_ \ / _ \ '__|
|_| \_|\___|\__|____/\___\__,_| | | | | | |  __/ |
                                |_| |_|_| |_|\___|_|
  Network Vulnerability Scanner — For authorised testing only
"""


def render_results(result) -> None:
    print(f"\n{'='*60}")
    print(f"  Target    : {result.target} ({result.ip_address})")
    print(f"  OS Guess  : {result.os_guess or 'Unknown'}")
    print(f"  Ports     : {result.total_ports_scanned} scanned, {len(result.open_ports)} open")
    print(f"  CVSS Max  : {result.risk_summary.get('max_cvss', 0):.1f}")
    print(f"{'='*60}")

    if not result.open_ports:
        print("  No open ports found.")
        return

    for p in result.open_ports:
        svc = p.service.name if p.service else "unknown"
        ver = p.service.version or ""
        tls = " [TLS]" if (p.service and p.service.tls) else ""
        print(f"\n  Port {p.port}/tcp  {p.state.value.upper():<10}  {svc} {ver}{tls}")
        for v in p.vulnerabilities:
            badge = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(v.severity, "🟢")
            print(f"    {badge} {v.cve_id}  CVSS {v.cvss_score}  {v.description[:60]}...")
            print(f"       Fix: {v.remediation}")

    summary = result.risk_summary
    print(f"\n{'='*60}")
    print(f"  Risk Summary: {summary.get('critical',0)} CRITICAL  "
          f"{summary.get('high',0)} HIGH  {summary.get('medium',0)} MEDIUM")
    print(f"{'='*60}\n")


async def run_scan(target: str, profile: str, output: str = None):
    ports = PORT_PROFILES[profile]
    print(f"\n[*] Scanning {target} — profile: {profile} ({len(ports)} ports)")
    scanner = AsyncPortScanner(timeout=1.5, max_concurrent=200)
    result = await scanner.scan_host(target, ports)
    render_results(result)
    if output:
        import json
        from dataclasses import asdict
        with open(output, "w") as f:
            json.dump(asdict(result), f, indent=2, default=str)
        print(f"[✓] Results saved to {output}")
    return result


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="Async network vulnerability scanner",
        epilog="⚠️  Only scan systems you own or have explicit written permission to test.",
    )
    parser.add_argument("--target", "-t", help="Target IP or hostname")
    parser.add_argument("--profile", "-p", choices=list(PORT_PROFILES.keys()), default="top100")
    parser.add_argument("--output", "-o", help="Save JSON results to file")
    parser.add_argument("--demo", action="store_true", help="Demo scan against localhost")
    args = parser.parse_args()

    if args.demo:
        asyncio.run(run_scan("127.0.0.1", "web", args.output))
    elif args.target:
        asyncio.run(run_scan(args.target, args.profile, args.output))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
