"""Scan orchestrator: runs modules in dependency order, computes risk, returns result."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from .models import ModuleResult, MXInfo, ScanConfig, ScanResult
from .modules import dane, dkim, dmarc, mta_sts, relay, smtp, spf, starttls, tls_rpt
from .modules import mx as mx_mod
from .modules.mx import MAX_SCORE as MX_MAX_SCORE
from .scoring.risk_engine import compute_score

MODULE_ORDER = [
    "mx",
    "spf",
    "dkim",
    "dmarc",
    "smtp",
    "starttls",
    "mta_sts",
    "tls_rpt",
    "dane",
    "relay",
]


def scan(
    domain: str,
    config: ScanConfig | None = None,
    on_progress: Callable[[str, float], None] | None = None,
) -> ScanResult:
    """Execute a full mail security scan against a domain."""
    cfg = config or ScanConfig(domain=domain)
    if not cfg.domain:
        cfg.domain = domain

    modules: dict[str, ModuleResult] = {}
    mx_hosts: list[MXInfo] = []
    dmarc_policy: dict = {}

    def _tick(stage: int, label: str) -> None:
        if on_progress is not None:
            on_progress(label, stage / 4.0)

    # ---- Stage 1: DNS-based modules (parallel) ----
    _tick(0, "mx/spf/dkim/dmarc")
    with ThreadPoolExecutor(max_workers=cfg.max_threads) as pool:
        fut_mx = pool.submit(mx_mod.run, cfg)
        fut_spf = pool.submit(spf.run, cfg)
        fut_dkim = pool.submit(dkim.run, cfg)
        fut_dmarc = pool.submit(dmarc.run, cfg)

        mx_mr, mx_hosts = fut_mx.result()
        mx_mr.score_contribution = 0.0
        mx_mr.max_score = MX_MAX_SCORE
        modules["mx"] = mx_mr

        modules["spf"] = fut_spf.result()
        modules["dkim"] = fut_dkim.result()

        dmarc_mr, dmarc_policy = fut_dmarc.result()
        modules["dmarc"] = dmarc_mr

    # ---- Stage 2: transport infra + SMTP handshake (parallel) ----
    _tick(1, "mta-sts/tls-rpt/dane/smtp")
    with ThreadPoolExecutor(max_workers=cfg.max_threads) as pool:
        fut_mta = pool.submit(mta_sts.run, cfg)
        fut_tls = pool.submit(tls_rpt.run, cfg)
        fut_dane = pool.submit(dane.run, cfg, mx_hosts)
        fut_smtp = pool.submit(smtp.run, cfg, mx_hosts)

    modules["mta_sts"] = fut_mta.result()
    modules["tls_rpt"] = fut_tls.result()
    modules["dane"] = fut_dane.result()
    modules["smtp"] = fut_smtp.result()

    # ---- Stage 3: STARTTLS handshake (sequential per MX) ----
    _tick(2, "starttls")
    modules["starttls"] = starttls.run(cfg, mx_hosts)

    # ---- Stage 4: active relay test (only with --active) ----
    _tick(3, "relay")
    modules["relay"] = relay.run(cfg, mx_hosts)

    # ---- Scoring ----
    _tick(4, "mail done")
    breakdown = compute_score(modules, dmarc_policy)

    scan_result = ScanResult(
        domain=cfg.domain,
        modules=[modules[k] for k in MODULE_ORDER],
        total_score=breakdown.total,
        risk_level=(
            "INCONCLUSIVE"
            if any(not modules[name].assessed for name in ("smtp", "starttls"))
            else breakdown.risk_level
        ),
        mx_hosts=mx_hosts,
    )
    scan_result.breakdown = breakdown  # type: ignore[attr-defined]
    return scan_result
