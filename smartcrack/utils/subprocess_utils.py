from __future__ import annotations
import subprocess
from typing import Sequence


def safe_run(command: Sequence[str], timeout: int = 3600) -> subprocess.CompletedProcess:
    return subprocess.run(list(command), capture_output=True, text=True, check=False, timeout=timeout)
