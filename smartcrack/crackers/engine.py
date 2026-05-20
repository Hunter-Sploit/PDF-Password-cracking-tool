from __future__ import annotations
from ..utils.subprocess_utils import safe_run


class CrackingEngine:
    def run(
        self,
        base_cmd: list[str],
        hash_file: str,
        wordlist: str | None = None,
        attack_mode: str = "dictionary",
        mask: str | None = None,
        rule: str | None = None,
        extra: list[str] | None = None,
    ):
        cmd = list(base_cmd)

        if cmd[0] == "hashcat":
            if attack_mode == "mask" and mask:
                cmd.extend(["-a", "3", hash_file, mask])
            else:
                if wordlist:
                    cmd.extend([hash_file, wordlist])
                else:
                    cmd.append(hash_file)
            if rule:
                cmd.extend(["-r", rule])
        else:
            if attack_mode == "mask" and mask:
                cmd.extend(["--mask", mask, hash_file])
            else:
                if wordlist:
                    cmd.extend([f"--wordlist={wordlist}", hash_file])
                else:
                    cmd.append(hash_file)
            if rule:
                cmd.extend([f"--rules={rule}"])

        if extra:
            cmd.extend(extra)
        return safe_run(cmd)
