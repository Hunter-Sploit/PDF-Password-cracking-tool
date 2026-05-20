from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from shutil import which
from typing import Dict
from ..utils.subprocess_utils import safe_run


@dataclass
class ExtractResult:
    ok: bool
    hash_value: str = ""
    extractor: str = ""
    error: str = ""


class JohnExtractorRegistry:
    EXTRACTOR_MAP: Dict[str, str] = {
        "pdf": "pdf2john",
        "zip": "zip2john",
        "rar": "rar2john",
        "office": "office2john",
        "ssh": "ssh2john",
        "7z": "7z2john.pl",
    }

    def extract(self, input_type: str, file_path: str) -> ExtractResult:
        extractor = self.EXTRACTOR_MAP.get(input_type)
        if not extractor:
            return ExtractResult(ok=False, error=f"No extractor mapped for {input_type}")
        if not which(extractor):
            return ExtractResult(ok=False, extractor=extractor, error=f"{extractor} not installed")

        completed = safe_run([extractor, str(Path(file_path))])
        if completed.returncode != 0:
            return ExtractResult(ok=False, extractor=extractor, error=completed.stderr.strip() or "extractor failed")
        first_line = (completed.stdout or "").splitlines()[0] if completed.stdout else ""
        return ExtractResult(ok=bool(first_line), extractor=extractor, hash_value=first_line, error="" if first_line else "empty extraction output")
