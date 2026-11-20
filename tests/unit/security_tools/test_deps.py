from unittest.mock import patch

import pytest
import typer

from eva.security_tools.deps import check_extra_available, missing_extra_exit


def test_check_extra_available_success():
    # If the extra is installed, check_extra_available returns None
    result = check_extra_available("web-images")
    assert result is None or "pip install" in result


def test_check_extra_available_missing_package():
    with patch("importlib.import_module", side_effect=ImportError("No module named fake_pkg")):
        hint = check_extra_available("sec")
        assert hint == 'pip install "eva-cli[sec]"'


def test_check_extra_available_sec_media_crypto_fallback():
    def mock_import(name):
        if name == "Crypto":
            raise ImportError("No Crypto")
        if name == "Cryptodome":
            return object()
        return object()

    with patch("importlib.import_module", side_effect=mock_import):
        hint = check_extra_available("sec-media")
        assert hint is None


def test_check_extra_available_sec_media_both_crypto_missing():
    def mock_import(name):
        if name in ("Crypto", "Cryptodome"):
            raise ImportError(f"No {name}")
        return object()

    with patch("importlib.import_module", side_effect=mock_import):
        hint = check_extra_available("sec-media")
        assert hint == 'pip install "eva-cli[sec-media]"'


def test_missing_extra_exit_raises_typer_exit(capsys):
    with pytest.raises(typer.Exit) as exc:
        missing_extra_exit("sec", "YARA scanning")
    assert exc.value.exit_code == 1
    captured = capsys.readouterr()
    # print_error output goes to stderr or stdout
    output = captured.out + captured.err
    assert "Feature 'YARA scanning' requires the 'sec' optional extra" in output
    assert 'pip install "eva-cli[sec]"' in output
