"""
Vulnerability Dashboard — REST API
====================================
Flask-based API serving scan results to the web dashboard.
Endpoints follow RESTful conventions with JSON responses.

Skills: Web API security, secure coding, authentication middleware
"""

import asyncio
import json
import os
import hashlib
import hmac
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from flask import Flask, request, jsonify, abort
from src.scanner import AsyncPortScanner, PORT_PROFILES, ScanResult
from dataclasses import asdict

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Simple API-key authentication middleware
# ---------------------------------------------------------------------------
# In production: use OAuth2 / JWT. API keys are for demo simplicity.

VALID_API_KEYS = {os.environ.get("API_KEY", "dev-key-change-in-production")}


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if not key or key not in VALID_API_KEYS:
            abort(401, description="Invalid or missing API key")
        return f(*args, **kwargs)
    return decorated


# In-memory scan result cache (use Redis in production)
_scan_cache: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/api/v1/health", methods=["GET"])
def health():
    """Health check — no auth required."""
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})


@app.route("/api/v1/scan", methods=["POST"])
@require_api_key
def start_scan():
    """
    Trigger a new port scan.
    Body: { "target": "192.168.1.1", "profile": "top100" }
    """
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target", "").strip()
    profile = data.get("profile", "top100")

    if not target:
        return jsonify({"error": "target is required"}), 400
    if profile not in PORT_PROFILES:
        return jsonify({"error": f"profile must be one of {list(PORT_PROFILES.keys())}"}), 400

    # Input validation — prevent SSRF to cloud metadata endpoints
    blocked_targets = ["169.254.169.254", "fd00:ec2::254", "metadata.google.internal"]
    if any(b in target for b in blocked_targets):
        return jsonify({"error": "Target not allowed (SSRF protection)"}), 403

    ports = PORT_PROFILES[profile]
    scanner = AsyncPortScanner(timeout=1.5, max_concurrent=128)

    try:
        result: ScanResult = asyncio.run(scanner.scan_host(target, ports))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    scan_id = hashlib.sha256(
        f"{target}{datetime.now().isoformat()}".encode()
    ).hexdigest()[:12]

    payload = asdict(result)
    _scan_cache[scan_id] = payload

    return jsonify({"scan_id": scan_id, "result": payload}), 200


@app.route("/api/v1/scan/<scan_id>", methods=["GET"])
@require_api_key
def get_scan(scan_id: str):
    """Retrieve a previously cached scan result."""
    result = _scan_cache.get(scan_id)
    if not result:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(result)


@app.route("/api/v1/scans", methods=["GET"])
@require_api_key
def list_scans():
    """List all cached scan IDs and targets."""
    summary = [
        {"scan_id": k, "target": v.get("target"), "completed": v.get("scan_completed")}
        for k, v in _scan_cache.items()
    ]
    return jsonify({"scans": summary, "total": len(summary)})


@app.route("/api/v1/vulnerabilities", methods=["GET"])
@require_api_key
def list_vulns():
    """Aggregate all vulnerabilities across all scans, sorted by CVSS score."""
    vulns = []
    for scan_id, scan in _scan_cache.items():
        for port in scan.get("open_ports", []):
            for v in port.get("vulnerabilities", []):
                vulns.append({**v, "scan_id": scan_id, "target": scan.get("target"), "port": port.get("port")})
    vulns.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
    return jsonify({"vulnerabilities": vulns, "total": len(vulns)})


if __name__ == "__main__":
    # Never use debug=True in production
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
