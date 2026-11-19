"""Web recon module wrappers. Each reuses an external tool via its JSON output.

Nothing inventive here: the scanner orchestrates battle-tested tools
(subfinder, gau, httpx, whatweb, naabu, testssl.sh, nuclei) and only parses
their structured output into uniform Findings.
"""

from . import discovery, ports, probe, tech, tls, vulns

__all__ = ["discovery", "ports", "probe", "tech", "tls", "vulns"]