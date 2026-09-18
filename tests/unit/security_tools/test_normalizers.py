import json

from eva.security_tools.normalizers import (
    findings_to_sarif,
    normalize_aegis,
    normalize_gitleaks,
    normalize_osv,
    normalize_report,
    normalize_sarif,
    normalize_semgrep,
    normalize_syft,
    normalize_trivy,
    normalize_zap,
)


def test_trivy_normalizer_redacts_secret():
    findings = normalize_trivy(
        {
            "Results": [
                {
                    "Target": "app.py",
                    "Secrets": [
                        {
                            "RuleID": "generic-api-key",
                            "Title": "API key",
                            "Severity": "HIGH",
                            "StartLine": 3,
                            "EndLine": 3,
                            "Match": "api_key=sk-1234567890abcdefghijklmnop",
                        }
                    ],
                }
            ]
        }
    )
    assert findings[0].tool == "trivy"
    assert findings[0].severity == "high"
    assert "[REDACTED" in findings[0].evidence


def test_semgrep_normalizer():
    findings = normalize_semgrep(
        {
            "results": [
                {
                    "check_id": "python.danger",
                    "path": "app.py",
                    "start": {"line": 10},
                    "end": {"line": 11},
                    "extra": {"message": "Dangerous call", "metadata": {"severity": "WARNING", "category": "sast"}},
                }
            ],
            "errors": [],
        }
    )
    assert findings[0].rule_id == "python.danger"
    assert findings[0].severity == "medium"


def test_gitleaks_normalizer():
    findings = normalize_gitleaks(
        [
            {
                "RuleID": "private-key",
                "Description": "Private key",
                "File": ".env",
                "StartLine": 1,
                "Secret": "secret=abc123abc123",
            }
        ]
    )
    assert findings[0].category == "secret"
    assert findings[0].confidence == "high"


def test_aegis_normalizer():
    findings = normalize_aegis(
        {
            "image_path": "evidence.png",
            "sha256": "abc",
            "structure": {"valid": False, "severity": "medium", "eof": "trailing data"},
        }
    )
    assert {finding.category for finding in findings} >= {"integrity", "forensics"}


def test_zap_normalizer():
    findings = normalize_zap(
        {
            "site": [
                {
                    "@name": "https://staging.example.internal",
                    "alerts": [
                        {
                            "pluginid": "10020",
                            "alert": "Missing header",
                            "riskdesc": "Low",
                            "confidence": "High",
                            "instances": [{"uri": "https://staging.example.internal/app"}],
                        }
                    ],
                }
            ]
        }
    )
    assert findings[0].tool == "zap"
    assert findings[0].severity == "low"
    assert findings[0].target.endswith("/app")


def test_sarif_round_trip():
    findings = normalize_semgrep(
        {
            "results": [
                {
                    "check_id": "x.rule",
                    "path": "x.py",
                    "start": {"line": 1},
                    "end": {"line": 1},
                    "extra": {"message": "Issue", "metadata": {"severity": "ERROR"}},
                }
            ],
            "errors": [],
        }
    )
    sarif = findings_to_sarif(findings)
    assert sarif["version"] == "2.1.0"
    reparsed = normalize_sarif(json.loads(json.dumps(sarif)))
    assert reparsed[0].rule_id == "x.rule"


def test_syft_normalizer():
    findings = normalize_syft(
        {
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "requests", "version": "2.28.1"},
                {"name": "urllib3", "version": "1.26.5"},
            ],
        }
    )
    assert len(findings) == 1
    assert findings[0].tool == "syft"
    assert findings[0].category == "sbom"
    assert "2 components" in findings[0].title


def test_osv_normalizer():
    findings = normalize_osv(
        {
            "results": [
                {
                    "source": {"path": "requirements.txt"},
                    "packages": [
                        {
                            "package": {"name": "jinja2", "version": "2.10"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-g3rq-g295-4j35",
                                    "summary": "Sandbox escape in Jinja2",
                                    "database_specific": {"severity": "HIGH"},
                                    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2019-10906"}],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )
    assert len(findings) == 1
    assert findings[0].tool == "osv-scanner"
    assert findings[0].rule_id == "GHSA-g3rq-g295-4j35"
    assert findings[0].severity == "high"


def test_normalize_report_auto_detect(tmp_path):
    # SARIF report
    sarif_file = tmp_path / "test.sarif"
    sarif_file.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "test-tool"}},
                        "results": [
                            {
                                "ruleId": "TEST01",
                                "level": "error",
                                "message": {"text": "Test alert"},
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    findings = normalize_report(sarif_file)
    assert len(findings) == 1
    assert findings[0].tool == "test-tool"
    assert findings[0].rule_id == "TEST01"

    # Syft report
    syft_file = tmp_path / "sbom.cdx.json"
    syft_file.write_text(
        json.dumps({"bomFormat": "CycloneDX", "components": [{"name": "foo"}]}),
        encoding="utf-8",
    )
    syft_findings = normalize_report(syft_file)
    assert len(syft_findings) == 1
    assert syft_findings[0].tool == "syft"
