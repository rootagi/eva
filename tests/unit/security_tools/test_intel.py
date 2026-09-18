import asyncio

import pytest
import respx
from typer.testing import CliRunner

from eva.cli.app import app
from eva.security_tools.intel_client import (
    IntelClient,
    detect_ioc_type,
    extract_iocs,
    is_internal_ip,
)

runner = CliRunner()


def test_detect_ioc_type():
    assert detect_ioc_type("CVE-2021-44228") == "cve"
    assert detect_ioc_type("cve-2023-1234") == "cve"
    assert detect_ioc_type("192.0.2.1") == "ipv4"
    assert detect_ioc_type("2001:db8::1") == "ipv6"
    assert detect_ioc_type("https://example.com/bad.exe") == "url"
    assert detect_ioc_type("http://attacker.org") == "url"
    assert detect_ioc_type("evil-domain.com") == "domain"
    assert detect_ioc_type("44d88612fea8a8f36de82e1278abb02f") == "md5"
    assert detect_ioc_type("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12") == "sha1"
    assert detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "sha256"
    # File extensions should not be classified as domains
    assert detect_ioc_type("script.py") == "unknown"
    assert detect_ioc_type("data.json") == "unknown"


def test_is_internal_ip():
    assert is_internal_ip("127.0.0.1") is True
    assert is_internal_ip("10.10.10.5") is True
    assert is_internal_ip("172.16.0.1") is True
    assert is_internal_ip("192.168.1.100") is True
    assert is_internal_ip("8.8.8.8") is False
    assert is_internal_ip("1.1.1.1") is False


@respx.mock
def test_fetch_cve_success():
    client = IntelClient()
    cve_id = "CVE-2021-44228"

    nvd_response = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI RCE"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                    "weaknesses": [{"description": [{"value": "CWE-502"}, {"value": "CWE-400"}]}],
                    "configurations": [
                        {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"}]}]}
                    ],
                    "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html"}],
                }
            }
        ]
    }

    respx.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}").respond(
        status_code=200, json=nvd_response
    )

    metadata, findings = asyncio.run(client.fetch_cve(cve_id))

    assert metadata["found"] is True
    assert metadata["cve_id"] == cve_id
    assert metadata["cvss"]["score"] == 10.0
    assert metadata["cvss"]["severity"] == "CRITICAL"
    assert "CWE-502" in metadata["cwes"]
    assert len(metadata["affected_cpes"]) >= 1

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == cve_id
    assert f.severity == "critical"
    assert "Apache Log4j2" in f.evidence


@respx.mock
def test_fetch_cve_not_found():
    client = IntelClient()
    cve_id = "CVE-1999-99999"

    respx.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}").respond(status_code=404)

    metadata, findings = asyncio.run(client.fetch_cve(cve_id))
    assert metadata["found"] is False
    assert "error" in metadata
    assert len(findings) == 0


def test_fetch_cve_invalid_format():
    client = IntelClient()
    with pytest.raises(ValueError):
        asyncio.run(client.fetch_cve("INVALID-CVE"))


def test_query_ioc_internal_ip():
    client = IntelClient()
    metadata, findings = asyncio.run(client.query_ioc("192.168.1.50"))

    assert metadata["internal"] is True
    assert len(findings) == 1
    assert findings[0].rule_id == "ioc.internal_ip"


@respx.mock
def test_query_ioc_external_otx_and_urlhaus():
    client = IntelClient()
    ioc = "malicious-site.example.com"

    respx.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{ioc}/general").respond(
        status_code=200,
        json={"pulse_info": {"count": 3, "pulses": [{"name": "Phishing Campaign"}]}},
    )

    respx.post("https://urlhaus-api.abuse.ch/v1/host/").respond(
        status_code=200,
        json={"query_status": "ok", "threat": "malware_download", "status": "active"},
    )

    metadata, findings = asyncio.run(client.query_ioc(ioc))
    assert metadata["type"] == "domain"
    assert "alienvault_otx" in metadata["sources"]
    assert metadata["sources"]["alienvault_otx"]["pulse_count"] == 3

    rule_ids = {f.rule_id for f in findings}
    assert "otx.threat_pulses" in rule_ids
    assert "urlhaus.malware_indicator" in rule_ids


def test_extract_iocs_unstructured():
    sample_text = """
    Incident Report:
    Attacker from IP 198.51.100.99 accessed internal server 10.0.0.15.
    Downloaded dropper from http://bad.domain.org/drop.exe
    SHA-256 hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    Vulnerability targeted: CVE-2021-44228.
    Contact: soc@example.com
    Note: file analysis in script.py and config.json.
    """

    extracted, findings = extract_iocs(sample_text)

    assert "CVE-2021-44228" in extracted["cves"]
    assert "198.51.100.99" in extracted["ipv4"]
    assert "10.0.0.15" in extracted["ipv4"]
    assert "http://bad.domain.org/drop.exe" in extracted["urls"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in extracted["sha256"]
    assert "soc@example.com" in extracted["emails"]

    # Ignored domain false positives
    assert "script.py" not in extracted["domains"]
    assert "config.json" not in extracted["domains"]

    assert len(findings) >= 4


# --- CLI Integration Tests ---


def test_cli_intel_cve_dry_run():
    result = runner.invoke(app, ["sec", "intel", "cve", "CVE-2021-44228", "--dry-run"])
    assert result.exit_code == 0
    assert "[Dry-Run]" in result.output
    assert "CVE-2021-44228" in result.output


def test_cli_intel_ioc_dry_run():
    result = runner.invoke(app, ["sec", "intel", "ioc", "198.51.100.1", "--dry-run"])
    assert result.exit_code == 0
    assert "[Dry-Run]" in result.output
    assert "198.51.100.1" in result.output


def test_cli_intel_extract_dry_run(tmp_path):
    log_file = tmp_path / "sample.log"
    log_file.write_text("Found IP 198.51.100.2", encoding="utf-8")
    result = runner.invoke(app, ["sec", "intel", "extract", str(log_file), "--dry-run"])
    assert result.exit_code == 0
    assert "[Dry-Run]" in result.output


def test_cli_intel_extract_live(tmp_path):
    log_file = tmp_path / "sample.log"
    log_file.write_text("Found IP 198.51.100.2 and CVE-2021-44228 and url http://test.com", encoding="utf-8")
    result = runner.invoke(app, ["sec", "intel", "extract", str(log_file), "--format", "json"])
    assert result.exit_code == 0
    assert "IOC extraction complete" in result.output
