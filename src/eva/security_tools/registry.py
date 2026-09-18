from __future__ import annotations

from eva.security_tools.aegis import AegisAdapter
from eva.security_tools.base import SecurityAdapter
from eva.security_tools.gitleaks import GitleaksAdapter
from eva.security_tools.osv import OSVScannerAdapter
from eva.security_tools.semgrep import SemgrepAdapter
from eva.security_tools.syft import SyftAdapter
from eva.security_tools.trivy import TrivyAdapter
from eva.security_tools.zap import ZapAdapter


def _build_registry() -> dict[str, SecurityAdapter]:
    trivy = TrivyAdapter()
    semgrep = SemgrepAdapter()
    gitleaks = GitleaksAdapter()
    osv = OSVScannerAdapter()
    syft = SyftAdapter()
    aegis = AegisAdapter()
    zap = ZapAdapter()
    return {
        "trivy.filesystem": trivy,
        "semgrep.scan": semgrep,
        "gitleaks.scan": gitleaks,
        "osv.scan": osv,
        "syft.sbom": syft,
        "aegis.analyze": aegis,
        "aegis.detect-stego": aegis,
        "aegis.scan-structure": aegis,
        "aegis.extract-hidden": aegis,
        "aegis.sanitize": aegis,
        "aegis.slice-bitplanes": aegis,
        "aegis.sign": aegis,
        "aegis.verify": aegis,
        "aegis.keygen": aegis,
        "aegis.sign-asymmetric": aegis,
        "aegis.verify-asymmetric": aegis,
        "aegis.embed": aegis,
        "aegis.extract": aegis,
        "aegis.palette-embed": aegis,
        "aegis.palette-extract": aegis,
        "aegis.meta-embed": aegis,
        "aegis.meta-extract": aegis,
        "aegis.split": aegis,
        "aegis.reconstruct": aegis,
        "aegis.fs-embed": aegis,
        "aegis.fs-extract": aegis,
        "aegis.timestomp": aegis,
        "aegis.shred": aegis,
        "zap.baseline": zap,
        "zap.active": zap,
    }


REGISTRY = _build_registry()


def get_adapter(name: str) -> SecurityAdapter:
    return REGISTRY[name]


def list_adapters() -> dict[str, SecurityAdapter]:
    return dict(REGISTRY)
