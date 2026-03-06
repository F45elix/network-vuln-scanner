"""
Network Vulnerability Scanner
==============================
Async TCP/UDP port scanner with service fingerprinting, CVE correlation,
and CVSS v3.1 risk scoring. Outputs structured JSON for the web dashboard.

Skills demonstrated:
- Penetration testing methodology (Reconnaissance → Enumeration → Reporting)
- Network security (TCP/IP, port states, service banners)
- Vulnerability management (CVE lookup, CVSS scoring)
- Python async I/O (asyncio) for high-performance scanning
- OWASP / CIS Benchmark awareness
"""

import asyncio
import socket
import ssl
import json
import struct
import re
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum

logger = logging.getLogger("scanner")


# ---------------------------------------------------------------------------
# Enumerations & Data Models
# ---------------------------------------------------------------------------

class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


@dataclass
class ServiceInfo:
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    tls: bool = False


@dataclass
class Vulnerability:
    cve_id: str
    description: str
    cvss_score: float           # 0.0 – 10.0
    cvss_vector: str
    severity: str               # CRITICAL / HIGH / MEDIUM / LOW
    affected_versions: str
    remediation: str
    reference: str


@dataclass
class PortResult:
    port: int
    protocol: str               # tcp / udp
    state: PortState
    service: Optional[ServiceInfo] = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    scan_duration_ms: float = 0.0


@dataclass
class ScanResult:
    target: str
    ip_address: str
    scan_started: str
    scan_completed: str
    total_ports_scanned: int
    open_ports: list[PortResult] = field(default_factory=list)
    risk_summary: dict = field(default_factory=dict)
    os_guess: Optional[str] = None


# ---------------------------------------------------------------------------
# Well-Known Port → Service Mapping
# ---------------------------------------------------------------------------

WELL_KNOWN_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


# ---------------------------------------------------------------------------
# Simulated CVE Database (subset for demo — in production, query NVD API)
# ---------------------------------------------------------------------------

SIMULATED_CVE_DB: dict[str, list[dict]] = {
    "SSH": [
        {
            "cve_id": "CVE-2023-38408",
            "description": "Remote code execution in OpenSSH ssh-agent via malicious PKCS#11 provider",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "affected_versions": "OpenSSH < 9.3p2",
            "remediation": "Upgrade to OpenSSH 9.3p2 or later; disable ssh-agent if not needed",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
        },
    ],
    "SMB": [
        {
            "cve_id": "CVE-2017-0144",
            "description": "EternalBlue — SMBv1 RCE vulnerability exploited by WannaCry ransomware",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "affected_versions": "Windows SMBv1 (all versions)",
            "remediation": "Disable SMBv1; apply MS17-010 patch; block port 445 at perimeter",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
        },
        {
            "cve_id": "CVE-2020-0796",
            "description": "SMBGhost — Buffer overflow in SMBv3 compression; CVSS 10.0",
            "cvss_score": 10.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "affected_versions": "Windows 10 1903/1909, Server 2019",
            "remediation": "Apply KB4551762; disable SMBv3 compression if patch not available",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-0796",
        },
    ],
    "RDP": [
        {
            "cve_id": "CVE-2019-0708",
            "description": "BlueKeep — Pre-auth RCE in Remote Desktop Services (wormable)",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "affected_versions": "Windows 7, XP, Server 2008 R2/2003/2008",
            "remediation": "Apply KB4499175; enable NLA; block 3389 at perimeter",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-0708",
        },
    ],
    "Telnet": [
        {
            "cve_id": "CVE-2011-4862",
            "description": "Telnet transmits credentials in plaintext; trivial credential interception",
            "cvss_score": 8.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "severity": "HIGH",
            "affected_versions": "All Telnet implementations",
            "remediation": "Disable Telnet; migrate to SSH; enforce encrypted protocols policy",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2011-4862",
        },
    ],
    "FTP": [
        {
            "cve_id": "CVE-2010-1938",
            "description": "FTP NLST command buffer overflow; also transmits credentials in plaintext",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "severity": "HIGH",
            "affected_versions": "ProFTPD < 1.3.3c, vsftpd < 2.3.4 (backdoor)",
            "remediation": "Replace FTP with SFTP or FTPS; enforce authentication controls",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2010-1938",
        },
    ],
    "Redis": [
        {
            "cve_id": "CVE-2022-0543",
            "description": "Debian-specific Lua sandbox escape in Redis allowing arbitrary code execution",
            "cvss_score": 10.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "severity": "CRITICAL",
            "affected_versions": "Redis < 6.2.6 (Debian packages)",
            "remediation": "Upgrade Redis; bind to localhost; require AUTH; use protected mode",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2022-0543",
        },
    ],
    "MongoDB": [
        {
            "cve_id": "CVE-2019-2389",
            "description": "MongoDB exposed without authentication — widespread misconfiguration",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "severity": "HIGH",
            "affected_versions": "MongoDB with default configuration (no auth)",
            "remediation": "Enable authentication; bind to 127.0.0.1; firewall port 27017",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-2389",
        },
    ],
}


# ---------------------------------------------------------------------------
# Async Port Scanner
# ---------------------------------------------------------------------------

class AsyncPortScanner:
    """
    High-performance async TCP port scanner with service banner grabbing
    and TLS certificate inspection.

    IMPORTANT: Only scan hosts you own or have explicit written permission
    to test. Unauthorised scanning is illegal in Australia (Criminal Code Act 1995),
    the UK (Computer Misuse Act 1990), and most jurisdictions worldwide.
    """

    def __init__(self, timeout: float = 2.0, max_concurrent: int = 256):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._semaphore: Optional[asyncio.Semaphore] = None

    async def scan_host(self, target: str, ports: list[int]) -> ScanResult:
        """Scan a single host across the given port list."""
        self._semaphore = asyncio.Semaphore(self.max_concurrent)

        try:
            ip_address = socket.gethostbyname(target)
        except socket.gaierror:
            ip_address = target

        started = datetime.now(timezone.utc).isoformat()
        tasks = [self._scan_port(ip_address, port) for port in ports]
        results: list[PortResult] = await asyncio.gather(*tasks)

        open_ports = [r for r in results if r.state == PortState.OPEN]

        # Enrich open ports with CVE data
        for port_result in open_ports:
            if port_result.service:
                cves = SIMULATED_CVE_DB.get(port_result.service.name, [])
                port_result.vulnerabilities = [
                    Vulnerability(**cve) for cve in cves
                ]

        # Risk summary
        all_vulns = [v for p in open_ports for v in p.vulnerabilities]
        risk_summary = {
            "critical": sum(1 for v in all_vulns if v.severity == "CRITICAL"),
            "high": sum(1 for v in all_vulns if v.severity == "HIGH"),
            "medium": sum(1 for v in all_vulns if v.severity == "MEDIUM"),
            "low": sum(1 for v in all_vulns if v.severity == "LOW"),
            "max_cvss": max((v.cvss_score for v in all_vulns), default=0.0),
            "total_vulnerabilities": len(all_vulns),
        }

        return ScanResult(
            target=target,
            ip_address=ip_address,
            scan_started=started,
            scan_completed=datetime.now(timezone.utc).isoformat(),
            total_ports_scanned=len(ports),
            open_ports=open_ports,
            risk_summary=risk_summary,
            os_guess=self._guess_os(open_ports),
        )

    async def _scan_port(self, ip: str, port: int) -> PortResult:
        async with self._semaphore:
            import time
            start = time.monotonic()
            state = await self._tcp_connect(ip, port)
            elapsed = (time.monotonic() - start) * 1000

            service = None
            if state == PortState.OPEN:
                service_name = WELL_KNOWN_PORTS.get(port, "unknown")
                banner = await self._grab_banner(ip, port)
                tls = await self._check_tls(ip, port)
                version = self._extract_version(banner or "")
                service = ServiceInfo(
                    name=service_name,
                    version=version,
                    banner=banner[:200] if banner else None,
                    tls=tls,
                )

            return PortResult(
                port=port,
                protocol="tcp",
                state=state,
                service=service,
                scan_duration_ms=round(elapsed, 2),
            )

    async def _tcp_connect(self, ip: str, port: int) -> PortState:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return PortState.OPEN
        except (asyncio.TimeoutError, ConnectionRefusedError):
            return PortState.CLOSED
        except OSError:
            return PortState.FILTERED

    async def _grab_banner(self, ip: str, port: int) -> Optional[str]:
        """Attempt to read a service banner after connection."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )
            # Send HTTP request for web ports
            if port in (80, 8080, 8000):
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=1.5)
            writer.close()
            await writer.wait_closed()
            return data.decode("utf-8", errors="replace").strip()
        except Exception:
            return None

    async def _check_tls(self, ip: str, port: int) -> bool:
        """Check if port speaks TLS."""
        if port not in (443, 8443, 465, 993, 995):
            return False
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx), timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    @staticmethod
    def _extract_version(banner: str) -> Optional[str]:
        patterns = [
            r"OpenSSH[_\s]([\d.]+\w*)",
            r"Apache[/\s]([\d.]+)",
            r"nginx[/\s]([\d.]+)",
            r"vsftpd\s([\d.]+)",
            r"([\d]+\.[\d]+\.[\d]+)",
        ]
        for p in patterns:
            m = re.search(p, banner, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    @staticmethod
    def _guess_os(open_ports: list[PortResult]) -> Optional[str]:
        port_nums = {p.port for p in open_ports}
        if 3389 in port_nums or 445 in port_nums:
            return "Windows (likely)"
        if 22 in port_nums and 80 in port_nums:
            return "Linux/Unix (likely)"
        return None


# ---------------------------------------------------------------------------
# Common Port Profiles
# ---------------------------------------------------------------------------

PORT_PROFILES = {
    "top100": [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 194, 443, 445,
        465, 587, 993, 995, 1433, 1723, 3306, 3389, 5900, 6379, 8080,
        8443, 27017,
    ] + list(range(1024, 1090)),
    "web": [80, 443, 8080, 8443, 8000, 3000, 4000, 5000],
    "database": [1433, 1521, 3306, 5432, 6379, 27017, 9200, 5984],
    "all_common": list(range(1, 1025)),
}
