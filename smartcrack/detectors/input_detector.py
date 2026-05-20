from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import re


@dataclass
class DetectionResult:
    kind: str
    confidence: float
    reason: str


class InputDetector:
    MAGIC = {
        b"%PDF-": "pdf",
        b"PK\x03\x04": "zip",
        b"Rar!\x1a\x07": "rar",
        b"7z\xbc\xaf'\x1c": "7z",
    }

    HASH_PATTERNS = [
        ("bcrypt", re.compile(r"^\$2[aby]\$\d{2}\$.{53}$")),
        ("ntlm", re.compile(r"^[A-Fa-f0-9]{32}$")),
        ("sha1", re.compile(r"^[A-Fa-f0-9]{40}$")),
        ("sha256", re.compile(r"^[A-Fa-f0-9]{64}$")),
        ("md5", re.compile(r"^[A-Fa-f0-9]{32}$")),
        ("jwt", re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")),
    ]

    def detect(self, target: str) -> DetectionResult:
        p = Path(target)
        if p.exists() and p.is_file():
            head = p.read_bytes()[:16]
            for sig, kind in self.MAGIC.items():
                if head.startswith(sig):
                    return DetectionResult(kind=kind, confidence=0.98, reason=f"magic bytes matched {kind}")
            lower = p.suffix.lower()
            if lower in {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}:
                return DetectionResult(kind="office", confidence=0.70, reason="office extension heuristic")
            if "shadow" in p.name:
                return DetectionResult(kind="linux-shadow", confidence=0.70, reason="filename heuristic")
            return DetectionResult(kind="unknown-file", confidence=0.30, reason="unrecognized file signature")

        for kind, pattern in self.HASH_PATTERNS:
            if pattern.match(target.strip()):
                return DetectionResult(kind="raw-hash", confidence=0.95, reason=f"string pattern matched {kind}")

        return DetectionResult(kind="unknown", confidence=0.10, reason="no heuristics matched")
