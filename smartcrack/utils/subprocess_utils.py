from __future__ import annotations
import subprocess

def safe_run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False)
