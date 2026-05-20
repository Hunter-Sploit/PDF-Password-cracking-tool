from __future__ import annotations
from ..utils.subprocess_utils import safe_run


class CrackingEngine:
    def run(self, base_cmd: list[str], hash_file: str, wordlist: str | None = None, extra: list[str] | None = None):
        cmd = list(base_cmd)
        if wordlist:
            if cmd[0] == "hashcat":
                cmd.extend([hash_file, wordlist])
            else:
                cmd.extend([f"--wordlist={wordlist}", hash_file])
        else:
            cmd.append(hash_file)
        if extra:
            cmd.extend(extra)
        return safe_run(cmd)
