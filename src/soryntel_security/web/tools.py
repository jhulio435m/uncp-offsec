"""Execution helpers for shelling out to external recon tools."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass


@dataclass
class ToolStatus:
    """Result of trying to locate a binary."""

    name: str
    present: bool
    path: str = ""

    def describe(self) -> str:
        return f"{self.path}" if self.present else "not on PATH"


_TOOL_DIRS = ["/opt/tools/go/bin", "/opt/tools/bin", "/usr/local/bin"]


def which(binary: str) -> str | None:
    """Locate a binary on PATH plus a few known tool directories."""
    found = shutil.which(binary)
    if found:
        return found
    for d in _TOOL_DIRS:
        candidate = f"{d}/{binary}"
        if shutil.which(candidate):
            return candidate
    return None


@dataclass
class ToolResult:
    """Captured output of a finished tool run."""

    tool: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def lines(self) -> list[str]:
        return [ln for ln in self.stdout.splitlines() if ln.strip()]

    def json_lines(self, source: str = "") -> list[str]:
        """Return stdout JSON lines by default, or from an output file path."""
        text = self.stdout
        if source:
            try:
                with open(source, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                return []
        return [ln for ln in text.splitlines() if ln.strip()]


def run(cmd: list[str], *, timeout: float | None = 120.0) -> ToolResult:
    """Run an external command and capture stdout/stderr."""
    tool = cmd[0].split("/")[-1]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return ToolResult(tool=tool, returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
    except subprocess.TimeoutExpired as exc:
        def text(value) -> str:
            if value is None:
                return ""
            return value.decode(errors="replace") if isinstance(value, bytes) else str(value)

        return ToolResult(
            tool=tool,
            returncode=-1,
            stdout=text(exc.stdout),
            stderr=text(exc.stderr),
            timed_out=True,
        )
    except (OSError, ValueError) as exc:
        return ToolResult(tool=tool, returncode=-2, stderr=str(exc))


@contextmanager
def temporary_list(items: list[str], *, prefix: str) -> Iterator[str]:
    """Provide a private, automatically removed target-list file."""
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix=prefix, suffix=".txt", delete=True
    ) as fh:
        fh.write("\n".join(items) + "\n")
        fh.flush()
        yield fh.name


@contextmanager
def temporary_output(*, prefix: str, suffix: str) -> Iterator[str]:
    """Provide an output filename that is removed whether the tool succeeds or fails."""
    descriptor, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    try:
        # Some tools refuse to overwrite an existing JSON file.
        import os

        os.close(descriptor)
        os.unlink(path)
        yield path
    finally:
        try:
            import os

            os.unlink(path)
        except FileNotFoundError:
            pass
