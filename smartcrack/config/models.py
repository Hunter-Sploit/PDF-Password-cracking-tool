from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class WordlistConfig:
    active: Optional[str] = None
    saved: Dict[str, str] = field(default_factory=dict)


@dataclass
class AppConfig:
    default_backend: str = "auto"
    wordlists: WordlistConfig = field(default_factory=WordlistConfig)
    config_path: Path = Path.home() / ".smartcrack" / "config.json"


@dataclass
class CrackSession:
    session_id: str
    input_path: str
    target_type: str
    backend: str
    command: List[str]
    status: str = "created"
    discovered_password: Optional[str] = None
