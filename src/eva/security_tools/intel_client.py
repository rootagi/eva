from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Any

import httpx

from eva.security_tools.models import Finding
from eva.security_tools.normalizers import make_finding

# Regex patterns for IOC extraction
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
RE_IPV4 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
RE_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:\b[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
)
RE_URL = re.compile(r"\bhttps?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+\b", re.IGNORECASE)
RE_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Common benign extensions / false positives for domains
IGNORED_DOMAIN_SUFFIXES = {
    ".py",
    ".pyc",
    ".pyd",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".txt",
    ".md",
    ".sh",
    ".so",
    ".dll",
    ".exe",
    ".bin",
    ".tar",
    ".gz",
    ".zip",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".lock",
    ".cfg",
    ".ini",
    ".conf",
    ".rs",
    ".go",
    ".c",
    ".h",
}


def detect_ioc_type(value: str) -> str:
    """Classify the type of an IOC string."""
    val = value.strip()
    if RE_CVE.fullmatch(val):
        return "cve"
    if RE_MD5.fullmatch(val):
        return "md5"
    if RE_SHA1.fullmatch(val):
        return "sha1"
    if RE_SHA256.fullmatch(val):
        return "sha256"
    if val.startswith(("http://", "https://")):
        return "url"
    if _is_valid_ipv4(val):
        return "ipv4"
    if _is_valid_ipv6(val):
        return "ipv6"
    if RE_DOMAIN.fullmatch(val) and not any(val.lower().endswith(s) for s in IGNORED_DOMAIN_SUFFIXES):
        return "domain"
    return "unknown"


def _is_valid_ipv4(s: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(s)
        return not ip.is_multicast and not ip.is_unspecified
    except ValueError:
        return False


def _is_valid_ipv6(s: str) -> bool:
    try:
        ip = ipaddress.IPv6Address(s)
        return not ip.is_multicast and not ip.is_unspecified
    except ValueError:
        return False


def is_internal_ip(s: str) -> bool:
    """Check if an IP address belongs to private/internal RFC space or loopback."""
    try:
        ip = ipaddress.ip_address(s)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


class IntelClient:
    """Asynchronous HTTP client for querying threat intelligence sources with

    safe fallback, rate-limiting, and retry logic.
    """

    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout

    async def fetch_cve(
        self,
        cve_id: str,
        api_key: str | None = None,
        artifact_path: str | None = None,
    ) -> tuple[dict[str, Any], list[Finding]]:
        """Fetch CVE vulnerability information from NIST NVD API v2."""
        cve_clean = cve_id.strip().upper()
        if not RE_CVE.match(cve_clean):
            raise ValueError(f"Invalid CVE identifier format: {cve_id}")

        nvd_key = api_key or os.environ.get("NVD_API_KEY")
        headers = {"User-Agent": "eva-cli-threat-intel/1.0"}
        if nvd_key:
            headers["apiKey"] = nvd_key

        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_clean}"
        findings: list[Finding] = []
        metadata: dict[str, Any] = {"cve_id": cve_clean, "found": False}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 404:
                    metadata["error"] = "CVE not found in NIST NVD database"
                    return metadata, findings
                if resp.status_code == 403 or resp.status_code == 429:
                    metadata["error"] = f"Rate limited or forbidden by NVD (HTTP {resp.status_code})"
                    return metadata, findings

                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:  # noqa: BLE001
                metadata["error"] = f"Failed to query NVD API: {exc}"
                return metadata, findings

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            metadata["error"] = "No vulnerability records returned"
            return metadata, findings

        cve_data = vulns[0].get("cve", {})
        metadata["found"] = True

        # Extract English description
        descriptions = cve_data.get("descriptions", [])
        en_desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                en_desc = d.get("value", "")
                break
        if not en_desc and descriptions:
            en_desc = descriptions[0].get("value", "")
        metadata["description"] = en_desc

        # Extract CVSS v3.1 or v3.0 metrics
        metrics = cve_data.get("metrics", {})
        cvss_info: dict[str, Any] = {}
        for m_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(m_key):
                m_obj = metrics[m_key][0]
                data_obj = m_obj.get("cvssData", {})
                cvss_info = {
                    "version": data_obj.get("version", ""),
                    "score": data_obj.get("baseScore", 0.0),
                    "severity": data_obj.get("baseSeverity") or m_obj.get("baseSeverity", "unknown"),
                    "vector": data_obj.get("vectorString", ""),
                }
                break

        metadata["cvss"] = cvss_info

        # Extract CWEs
        cwes: list[str] = []
        for weakness in cve_data.get("weaknesses", []):
            for desc_w in weakness.get("description", []):
                val = desc_w.get("value")
                if val and val != "NVD-CWE-noinfo":
                    cwes.append(val)
        metadata["cwes"] = sorted(set(cwes))

        # Extract affected CPEs
        cpes: list[str] = []
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria")
                    if criteria:
                        cpes.append(criteria)
        metadata["affected_cpes"] = sorted(set(cpes))[:30]

        # References
        refs = [r.get("url") for r in cve_data.get("references", []) if r.get("url")]
        metadata["references"] = refs[:10]

        severity = str(cvss_info.get("severity", "medium")).lower()
        score = cvss_info.get("score", "unknown")
        findings.append(
            make_finding(
                tool="intel-cve",
                rule_id=cve_clean,
                title=f"{cve_clean} - CVSS {score} ({severity.upper()})",
                severity=severity,
                confidence="high",
                category="vulnerability",
                evidence=f"{en_desc}\nWeaknesses: {', '.join(metadata['cwes']) or 'None reported'}",
                remediation=f"Assess impact on affected CPEs ({len(cpes)} configurations matched) and apply vendor patches.",
                references=metadata["references"],
                artifact_path=artifact_path,
            )
        )

        return metadata, findings

    async def query_ioc(
        self,
        ioc_value: str,
        artifact_path: str | None = None,
    ) -> tuple[dict[str, Any], list[Finding]]:
        """Query open threat intelligence feeds (AlienVault OTX, URLhaus, AbuseIPDB) for an IOC."""
        ioc_clean = ioc_value.strip()
        ioc_type = detect_ioc_type(ioc_clean)

        metadata: dict[str, Any] = {
            "ioc": ioc_clean,
            "type": ioc_type,
            "internal": False,
            "sources": {},
        }
        findings: list[Finding] = []

        # Check for internal/private IP
        if ioc_type in {"ipv4", "ipv6"} and is_internal_ip(ioc_clean):
            metadata["internal"] = True
            metadata["notice"] = (
                f"IP address {ioc_clean} is a private/internal RFC address; public threat feeds omitted."
            )
            findings.append(
                make_finding(
                    tool="intel-ioc",
                    rule_id="ioc.internal_ip",
                    title=f"Internal / Private RFC address: {ioc_clean}",
                    severity="info",
                    category="internal_network",
                    evidence=f"{ioc_clean} is reserved for private or loopback networking.",
                    artifact_path=artifact_path,
                )
            )
            return metadata, findings

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # 1. AlienVault OTX (Free unauthenticated API)
            otx_type_map = {
                "ipv4": "IPv4",
                "ipv6": "IPv6",
                "domain": "domain",
                "url": "url",
                "md5": "file",
                "sha1": "file",
                "sha256": "file",
            }
            otx_type = otx_type_map.get(ioc_type)
            if otx_type:
                try:
                    otx_url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc_clean}/general"
                    otx_resp = await client.get(otx_url, headers={"User-Agent": "eva-cli-threat-intel/1.0"})
                    if otx_resp.status_code == 200:
                        otx_data = otx_resp.json()
                        pulse_info = otx_data.get("pulse_info", {})
                        pulse_count = pulse_info.get("count", 0)
                        pulses = pulse_info.get("pulses", [])
                        pulse_names = [p.get("name", "") for p in pulses[:5]]

                        metadata["sources"]["alienvault_otx"] = {
                            "pulse_count": pulse_count,
                            "top_pulses": pulse_names,
                        }

                        if pulse_count > 0:
                            findings.append(
                                make_finding(
                                    tool="intel-otx",
                                    rule_id="otx.threat_pulses",
                                    title=f"OTX Threat Intel: {ioc_clean} flagged in {pulse_count} pulse(s)",
                                    severity="high" if pulse_count >= 5 else "medium",
                                    confidence="high",
                                    category="threat_feed",
                                    evidence=f"Associated threat pulses: {', '.join(pulse_names)}",
                                    references=[f"https://otx.alienvault.com/indicator/{otx_type}/{ioc_clean}"],
                                    artifact_path=artifact_path,
                                )
                            )
                except Exception as exc:  # noqa: BLE001
                    metadata["sources"]["alienvault_otx"] = {"error": str(exc)}

            # 2. URLhaus (Free unauthenticated API for URLs, domains, and payload hashes)
            if ioc_type in {"url", "domain", "md5", "sha256"}:
                try:
                    urlhaus_endpoint = "https://urlhaus-api.abuse.ch/v1/"
                    urlhaus_data: dict[str, str] = {}
                    if ioc_type == "url":
                        urlhaus_endpoint += "url/"
                        urlhaus_data = {"url": ioc_clean}
                    elif ioc_type == "domain":
                        urlhaus_endpoint += "host/"
                        urlhaus_data = {"host": ioc_clean}
                    elif ioc_type in {"md5", "sha256"}:
                        urlhaus_endpoint += "payload/"
                        urlhaus_data = {"md5_hash": ioc_clean} if ioc_type == "md5" else {"sha256_hash": ioc_clean}

                    uh_resp = await client.post(urlhaus_endpoint, data=urlhaus_data)
                    if uh_resp.status_code == 200:
                        uh_json = uh_resp.json()
                        query_status = uh_json.get("query_status")
                        metadata["sources"]["urlhaus"] = {
                            "query_status": query_status,
                            "threat": uh_json.get("threat") or uh_json.get("signature"),
                            "status": uh_json.get("url_status") or uh_json.get("status"),
                        }
                        if query_status in {"ok", "active"}:
                            threat_label = uh_json.get("threat") or uh_json.get("signature") or "Malicious payload"
                            findings.append(
                                make_finding(
                                    tool="intel-urlhaus",
                                    rule_id="urlhaus.malware_indicator",
                                    title=f"URLhaus Malware Indicator: {ioc_clean} ({threat_label})",
                                    severity="critical"
                                    if "active" in str(uh_json.get("url_status", "")).lower()
                                    else "high",
                                    confidence="high",
                                    category="malware",
                                    evidence=f"Threat: {threat_label}; Status: {uh_json.get('url_status') or uh_json.get('status')}",
                                    references=[uh_json.get("urlhaus_reference", "https://urlhaus.abuse.ch/")],
                                    artifact_path=artifact_path,
                                )
                            )
                except Exception as exc:  # noqa: BLE001
                    metadata["sources"]["urlhaus"] = {"error": str(exc)}

            # 3. AbuseIPDB (Optional API key)
            abuse_key = os.environ.get("ABUSEIPDB_API_KEY")
            if ioc_type in {"ipv4", "ipv6"}:
                if abuse_key:
                    try:
                        abuse_resp = await client.get(
                            "https://api.abuseipdb.com/api/v2/check",
                            params={"ipAddress": ioc_clean, "maxAgeInDays": 90},
                            headers={"Key": abuse_key, "Accept": "application/json"},
                        )
                        if abuse_resp.status_code == 200:
                            abuse_data = abuse_resp.json().get("data", {})
                            score = abuse_data.get("abuseConfidenceScore", 0)
                            metadata["sources"]["abuseipdb"] = {
                                "abuse_confidence_score": score,
                                "total_reports": abuse_data.get("totalReports", 0),
                                "country": abuse_data.get("countryCode"),
                                "usage_type": abuse_data.get("usageType"),
                            }
                            if score >= 20:
                                severity = "critical" if score >= 80 else "high" if score >= 50 else "medium"
                                findings.append(
                                    make_finding(
                                        tool="intel-abuseipdb",
                                        rule_id="abuseipdb.reputation",
                                        title=f"AbuseIPDB Score {score}% for IP {ioc_clean}",
                                        severity=severity,
                                        confidence="high",
                                        category="reputation",
                                        evidence=f"Abuse confidence: {score}%; Reports: {abuse_data.get('totalReports')}; Usage: {abuse_data.get('usageType')}",
                                        references=[f"https://www.abuseipdb.com/check/{ioc_clean}"],
                                        artifact_path=artifact_path,
                                    )
                                )
                    except Exception as exc:  # noqa: BLE001
                        metadata["sources"]["abuseipdb"] = {"error": str(exc)}
                else:
                    metadata["sources"]["abuseipdb"] = {"status": "unconfigured (ABUSEIPDB_API_KEY not set)"}

            # 4. VirusTotal (Optional API key)
            vt_key = os.environ.get("VT_API_KEY")
            if vt_key and ioc_type in {"ipv4", "domain", "md5", "sha256"}:
                try:
                    vt_path_map = {
                        "ipv4": f"ip_addresses/{ioc_clean}",
                        "domain": f"domains/{ioc_clean}",
                        "md5": f"files/{ioc_clean}",
                        "sha256": f"files/{ioc_clean}",
                    }
                    vt_endpoint = f"https://www.virustotal.com/api/v3/{vt_path_map[ioc_type]}"
                    vt_resp = await client.get(vt_endpoint, headers={"x-apikey": vt_key})
                    if vt_resp.status_code == 200:
                        vt_attrs = vt_resp.json().get("data", {}).get("attributes", {})
                        stats = vt_attrs.get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        metadata["sources"]["virustotal"] = {
                            "malicious": malicious,
                            "suspicious": suspicious,
                            "harmless": stats.get("harmless", 0),
                        }
                        if malicious > 0:
                            findings.append(
                                make_finding(
                                    tool="intel-virustotal",
                                    rule_id="virustotal.detections",
                                    title=f"VirusTotal Detections: {malicious} engine(s) flagged {ioc_clean}",
                                    severity="critical" if malicious >= 5 else "high",
                                    confidence="high",
                                    category="reputation",
                                    evidence=f"Malicious detections: {malicious}; Suspicious: {suspicious}",
                                    references=[f"https://www.virustotal.com/gui/search/{ioc_clean}"],
                                    artifact_path=artifact_path,
                                )
                            )
                except Exception as exc:  # noqa: BLE001
                    metadata["sources"]["virustotal"] = {"error": str(exc)}
            elif not vt_key:
                metadata["sources"]["virustotal"] = {"status": "unconfigured (VT_API_KEY not set)"}

        return metadata, findings


def extract_iocs(
    text_or_path: str | Path, artifact_path: str | None = None
) -> tuple[dict[str, list[str]], list[Finding]]:
    """Parse unstructured logs, markdown reports, or text files to extract

    and deduplicate all IOCs using strict regex patterns.
    """
    raw_text = ""
    source_name = "text"

    if isinstance(text_or_path, Path) or (
        isinstance(text_or_path, str) and "\n" not in text_or_path and Path(text_or_path).is_file()
    ):
        p = Path(text_or_path)
        source_name = str(p)
        raw_text = p.read_text(encoding="utf-8", errors="replace")
    else:
        raw_text = str(text_or_path)

    # Extraction from raw_text to preserve hashes and structured patterns
    cves = sorted(set(RE_CVE.findall(raw_text)))
    urls = sorted(set(RE_URL.findall(raw_text)))
    md5s = sorted(set(RE_MD5.findall(raw_text)))
    sha1s = sorted(set(RE_SHA1.findall(raw_text)))
    sha256s = sorted(set(RE_SHA256.findall(raw_text)))
    emails = sorted(set(RE_EMAIL.findall(raw_text)))

    # Filter IPv4
    raw_ips = RE_IPV4.findall(raw_text)
    valid_ipv4s = sorted({ip for ip in raw_ips if _is_valid_ipv4(ip)})

    # Filter Domains: strip false positives, file names, URLs
    raw_domains = RE_DOMAIN.findall(raw_text)
    valid_domains = set()
    for dom in raw_domains:
        d_lower = dom.lower()
        if any(d_lower.endswith(sfx) for sfx in IGNORED_DOMAIN_SUFFIXES):
            continue
        if _is_valid_ipv4(dom):
            continue
        valid_domains.add(dom)
    domains = sorted(valid_domains)

    extracted: dict[str, list[str]] = {
        "cves": cves,
        "ipv4": valid_ipv4s,
        "domains": domains,
        "urls": urls,
        "md5": md5s,
        "sha1": sha1s,
        "sha256": sha256s,
        "emails": emails,
    }

    findings: list[Finding] = []

    for cve in cves:
        findings.append(
            make_finding(
                tool="intel-extract",
                rule_id="extract.cve",
                title=f"Extracted CVE reference: {cve}",
                severity="medium",
                category="cve_reference",
                file=source_name,
                evidence=f"Found {cve} in extracted text",
                artifact_path=artifact_path,
            )
        )

    for ip in valid_ipv4s:
        is_priv = is_internal_ip(ip)
        findings.append(
            make_finding(
                tool="intel-extract",
                rule_id="extract.ipv4",
                title=f"Extracted {'internal' if is_priv else 'public'} IP: {ip}",
                severity="low" if is_priv else "medium",
                category="ioc_ip",
                file=source_name,
                evidence=f"IP address {ip} extracted from source text",
                artifact_path=artifact_path,
            )
        )

    for url in urls[:50]:
        findings.append(
            make_finding(
                tool="intel-extract",
                rule_id="extract.url",
                title=f"Extracted URL: {url}",
                severity="medium",
                category="ioc_url",
                file=source_name,
                evidence=f"URL {url} extracted from source text",
                artifact_path=artifact_path,
            )
        )

    for sha in sha256s:
        findings.append(
            make_finding(
                tool="intel-extract",
                rule_id="extract.sha256",
                title=f"Extracted SHA-256 hash: {sha}",
                severity="info",
                category="ioc_hash",
                file=source_name,
                evidence=f"SHA-256 hash {sha} extracted from source text",
                artifact_path=artifact_path,
            )
        )

    return extracted, findings
