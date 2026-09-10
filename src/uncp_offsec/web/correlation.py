"""Cross-engine finding correlation without hiding original evidence."""

from __future__ import annotations

import re

from mailsec.models import Finding, ModuleResult, Severity

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


def run(modules: dict[str, ModuleResult]) -> ModuleResult:
    result = ModuleResult(name="correlation")
    groups: dict[str, list[tuple[str, Finding]]] = {}
    for module_name, module in modules.items():
        if module_name == "correlation":
            continue
        for finding in module.findings:
            text = f"{finding.title} {finding.detail} {finding.rfc_ref} {' '.join(finding.cve_ids)}"
            keys = {value.upper() for value in CVE_RE.findall(text) + CWE_RE.findall(text)}
            if not keys and finding.severity not in (Severity.INFO, Severity.PASS):
                normalized = re.sub(r"\W+", " ", finding.title.lower()).strip()
                if normalized:
                    keys.add(f"TITLE:{normalized}")
            for key in keys:
                groups.setdefault(key, []).append((module_name, finding))
    correlated = {key: rows for key, rows in groups.items() if len({module for module, _ in rows}) >= 2}
    result.assessed = True
    if not correlated:
        result.findings.append(Finding("correlation", Severity.INFO, "No cross-engine correlations", "Original findings remain available independently.", ""))
        return result
    for key, rows in sorted(correlated.items()):
        modules_seen = sorted({module for module, _ in rows})
        worst = min((finding.severity for _, finding in rows), key=lambda severity: severity.weight)
        result.findings.append(Finding("correlation", worst, f"Correlated signal: {key}", f"Engines: {', '.join(modules_seen)}\n" + "\n".join(f"{module}: {finding.title}" for module, finding in rows[:20]), "Prioritize manual validation because independent engines reported the same weakness identifier.", confidence="HIGH", verification_status="CORRELATED", occurrence_count=len(rows)))
    return result
