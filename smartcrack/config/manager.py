from __future__ import annotations
import json
from pathlib import Path
from .models import AppConfig, WordlistConfig


class ConfigManager:
    def __init__(self, path: Path | None = None):
        self.path = path or AppConfig().config_path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> AppConfig:
        if not self.path.exists():
            return AppConfig(config_path=self.path)
        data = json.loads(self.path.read_text())
        wl = WordlistConfig(active=data.get("wordlists", {}).get("active"), saved=data.get("wordlists", {}).get("saved", {}))
        return AppConfig(default_backend=data.get("default_backend", "auto"), wordlists=wl, config_path=self.path)

    def save(self, config: AppConfig) -> None:
        payload = {
            "default_backend": config.default_backend,
            "wordlists": {"active": config.wordlists.active, "saved": config.wordlists.saved},
        }
        self.path.write_text(json.dumps(payload, indent=2))
