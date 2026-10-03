import subprocess
import sys

from eva.providers import PROVIDER_MAP, get_provider


def test_cli_app_import_does_not_load_heavy_sdks():
    """Importing eva.cli.app must not eagerly import heavy LLM SDKs or security_tools."""
    code = (
        "import sys, eva.cli.app; "
        "heavy = ['google.genai', 'openai', 'eva.agent.loop', 'eva.security_tools.cli']; "
        "loaded = [m for m in heavy if m in sys.modules]; "
        "assert not loaded, f'Eagerly loaded heavy modules: {loaded}'"
    )
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stderr


def test_providers_init_lazy_registry():
    """Importing eva.providers must not eagerly import provider modules until requested."""
    code = (
        "import sys, eva.providers; "
        "eager = [m for m in eva.providers.PROVIDER_MAP.values() if m in sys.modules]; "
        "assert not eager, f'Eagerly loaded provider modules: {eager}'; "
        "assert 'openai' not in sys.modules; "
        "assert 'google.genai' not in sys.modules"
    )
    res = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stderr

    for name in PROVIDER_MAP:
        provider = get_provider(name)
        assert provider is not None
        assert provider.name == name
