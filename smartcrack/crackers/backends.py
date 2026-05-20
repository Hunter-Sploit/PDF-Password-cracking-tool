from __future__ import annotations
from dataclasses import dataclass
from shutil import which
from typing import List


@dataclass
class CrackCommand:
    backend: str
    command: List[str]


class BackendSelector:
    JOHN_PREFERRED = {"pdf", "zip", "rar", "office", "7z", "ssh", "keepass", "wpa"}

    def available(self) -> dict:
        return {"hashcat": bool(which("hashcat")), "john": bool(which("john"))}

    def select(self, hashcat_mode: str, john_format: str, prefer: str = "auto") -> CrackCommand:
        avail = self.available()
        if prefer == "hashcat":
            if not avail["hashcat"]:
                raise RuntimeError("Requested hashcat backend but hashcat is not installed")
            return CrackCommand("hashcat", ["hashcat", "-m", hashcat_mode])
        if prefer == "john":
            if not avail["john"]:
                raise RuntimeError("Requested john backend but john is not installed")
            return CrackCommand("john", ["john", f"--format={john_format}"])

        # auto strategy
        if john_format in self.JOHN_PREFERRED and avail["john"]:
            return CrackCommand("john", ["john", f"--format={john_format}"])
        if hashcat_mode and hashcat_mode != "0" and avail["hashcat"]:
            return CrackCommand("hashcat", ["hashcat", "-m", hashcat_mode])
        if avail["john"]:
            return CrackCommand("john", ["john", f"--format={john_format}"])
        if avail["hashcat"]:
            return CrackCommand("hashcat", ["hashcat", "-m", hashcat_mode])
        raise RuntimeError("No cracking backend found. Install hashcat and/or john.")
