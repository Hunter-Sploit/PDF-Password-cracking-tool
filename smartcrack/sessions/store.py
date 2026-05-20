from __future__ import annotations
import json
from pathlib import Path
from ..config.models import CrackSession


class SessionStore:
    def __init__(self, base: Path | None = None):
        self.base = base or Path.home() / ".smartcrack" / "sessions"
        self.base.mkdir(parents=True, exist_ok=True)

    def save(self, s: CrackSession):
        path = self.base / f"{s.session_id}.json"
        path.write_text(json.dumps(s.__dict__, indent=2))

    def list_sessions(self):
        return sorted(self.base.glob("*.json"))
