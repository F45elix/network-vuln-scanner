# 🔍 Network Vulnerability Scanner

> **Skills demonstrated:** Penetration testing · Network security · CVE/CVSS scoring · Async Python · REST API · SSRF protection · Secure coding

A high-performance async TCP port scanner with CVE correlation, CVSS v3.1 risk scoring, and a Flask REST API powering a vulnerability management dashboard — mirroring tools like **Nmap**, **Nessus**, and **Rapid7 InsightVM**.

---

## ⚠️ Legal Notice

> This tool is for **authorised penetration testing and security research only**.  
> Scanning systems without explicit written permission is **illegal** under:
> - 🇦🇺 Australia: *Criminal Code Act 1995* (s.477.1)  
> - 🇬🇧 UK: *Computer Misuse Act 1990* (s.1–3)  
> Only scan systems you own or have written authorisation to test.

---

## 📋 Why This Project

Key skills from Australian/UK visa-sponsored pentesting roles:

| Skill | Implementation |
|---|---|
| Penetration testing methodology | Recon → Enum → Exploitation risk scoring |
| Network protocols (TCP/IP) | Raw async TCP connect scanning |
| Vulnerability management | CVE DB lookup + CVSS 3.1 scoring |
| OWASP API Security | API key auth, SSRF protection, input validation |
| Python asyncio | 200+ concurrent scans via semaphore-limited async |
| REST API development | Flask API with proper HTTP status codes |

---

## 🚀 Quick Start

```bash
git clone https://github.com/F45elix/network-vuln-scanner.git
cd network-vuln-scanner

pip install -r requirements.txt

# CLI scan (localhost demo — no auth needed)
python main.py --demo

# Scan a target you own
python main.py --target 192.168.1.1 --profile top100 --output results.json

# Start the API server
export API_KEY=your-secret-key
python app.py

# Query the API
curl -H "X-API-Key: your-secret-key" \
  -X POST http://localhost:5000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "profile": "web"}'
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Health check |
| `POST` | `/api/v1/scan` | Trigger new scan |
| `GET` | `/api/v1/scan/<id>` | Get scan result |
| `GET` | `/api/v1/scans` | List all scans |
| `GET` | `/api/v1/vulnerabilities` | All CVEs sorted by CVSS |

All endpoints (except health) require `X-API-Key` header.

---

## 📊 Sample Output

```
  Port 22/tcp   OPEN       SSH 8.9p1
    🔴 CVE-2023-38408  CVSS 9.8  Remote code execution in OpenSSH ssh-agent...
       Fix: Upgrade to OpenSSH 9.3p2 or later

  Port 445/tcp  OPEN       SMB
    🔴 CVE-2017-0144    CVSS 9.8  EternalBlue — SMBv1 RCE (WannaCry)...
    🔴 CVE-2020-0796    CVSS 10.0 SMBGhost — SMBv3 compression buffer overflow...

  Risk Summary: 3 CRITICAL  1 HIGH  0 MEDIUM
```

---

## 🏗 Architecture

```
┌─────────────┐    async    ┌─────────────────┐    lookup    ┌──────────┐
│    CLI /    │────────────▶│ AsyncPortScanner │─────────────▶│  CVE DB  │
│  Flask API  │             │                  │              │ (NVD-sim)│
└─────────────┘             │ • TCP connect    │              └──────────┘
                            │ • Banner grab    │
                            │ • TLS check      │
                            │ • OS fingerprint │
                            └─────────────────┘
```

---

## 🔒 Security Features

- **SSRF Protection**: Blocks scanning of cloud metadata endpoints (169.254.169.254)
- **API Key Auth**: All scan endpoints require authentication
- **Input Validation**: Target and profile inputs are strictly validated
- **Rate Limiting**: Semaphore-controlled concurrency prevents network flooding
