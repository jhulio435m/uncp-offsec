"""UncP OffSec - unified offensive-surface assessment orchestration.

Wraps the MailSec email tool plus a pipeline of battle-tested web recon tools
(subfinder, gau, httpx, whatweb, naabu, testssl.sh, nuclei) and produces a
single scored, browsable report.
"""

__version__ = "0.2.0"

from mailsec.models import Severity

__all__ = ["Severity", "__version__"]
