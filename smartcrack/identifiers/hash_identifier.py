from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List


@dataclass
class HashGuess:
    algorithm: str
    hashcat_mode: str
    john_format: str
    confidence: float


class HashIdentifier:
    RULES = [
        ("bcrypt", re.compile(r"^\$2[aby]\$"), "3200", "bcrypt", 0.99),
        ("md5", re.compile(r"^[A-Fa-f0-9]{32}$"), "0", "raw-md5", 0.70),
        ("ntlm", re.compile(r"^[A-Fa-f0-9]{32}$"), "1000", "nt", 0.80),
        ("sha1", re.compile(r"^[A-Fa-f0-9]{40}$"), "100", "raw-sha1", 0.95),
        ("sha256", re.compile(r"^[A-Fa-f0-9]{64}$"), "1400", "raw-sha256", 0.95),
        ("jwt-hs256", re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"), "16500", "HMAC-SHA256", 0.65),
        ("pdf", re.compile(r"\$pdf\$"), "10400", "pdf", 0.98),
        ("zip", re.compile(r"\$pkzip\$"), "17200", "zip", 0.98),
    ]

    def identify(self, hash_input: str) -> List[HashGuess]:
        guesses = []
        txt = hash_input.strip()
        for algo, rule, hmode, jfmt, conf in self.RULES:
            if rule.search(txt):
                guesses.append(HashGuess(algo, hmode, jfmt, conf))
        return sorted(guesses, key=lambda g: g.confidence, reverse=True)
