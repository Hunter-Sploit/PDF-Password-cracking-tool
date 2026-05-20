from __future__ import annotations
from dataclasses import dataclass
from shutil import which
from typing import List


@dataclass
class CrackCommand:
    backend: str
    command: List[str]


class BackendSelector:
    def available(self) -> dict:
        return {"hashcat": bool(which("hashcat")), "john": bool(which("john"))}

    def select(self, hashcat_mode: str, john_format: str, prefer: str = "auto") -> CrackCommand:
        avail = self.available()
        if prefer == "hashcat" and avail["hashcat"]:
            return CrackCommand("hashcat", ["hashcat", "-m", hashcat_mode])
        if prefer == "john" and avail["john"]:
            return CrackCommand("john", ["john", f"--format={john_format}"])
        if avail["hashcat"]:
            return CrackCommand("hashcat", ["hashcat", "-m", hashcat_mode])
        if avail["john"]:
            return CrackCommand("john", ["john", f"--format={john_format}"])
        raise RuntimeError("No cracking backend found. Install hashcat and/or john.")
