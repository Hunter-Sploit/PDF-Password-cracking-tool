from __future__ import annotations
import argparse
import json
import uuid
from pathlib import Path
from shutil import which

from .config.manager import ConfigManager
from .config.models import CrackSession
from .crackers.backends import BackendSelector
from .crackers.engine import CrackingEngine
from .detectors.input_detector import InputDetector
from .extractors.john_extractors import JohnExtractorRegistry
from .identifiers.hash_identifier import HashIdentifier
from .recommender import recommend
from .sessions.store import SessionStore


AUTHORIZED_USE = "Authorized use only. Crack only assets you own or have explicit permission to test."


def _read_hash_input(input_value: str) -> str:
    src = Path(input_value)
    if src.exists() and src.is_file():
        lines = [ln.strip() for ln in src.read_text().splitlines() if ln.strip()]
        if not lines:
            raise SystemExit("Input file contains no hashes")
        return lines[0]
    return input_value


def cmd_identify(input_value: str) -> int:
    data = _read_hash_input(input_value)
    guesses = HashIdentifier().identify(data)
    if not guesses:
        print("No hash matches found.")
        return 1
    print("Algorithm\tHashcat\tJohn\tConfidence")
    for g in guesses:
        print(f"{g.algorithm}\t{g.hashcat_mode}\t{g.john_format}\t{g.confidence:.2f}")
    return 0


def cmd_wordlists(add: str | None, use: str | None, show: bool) -> int:
    cm = ConfigManager()
    cfg = cm.load()
    if add:
        p = Path(add)
        if not p.exists() or not p.is_file():
            raise SystemExit(f"wordlist does not exist: {add}")
        cfg.wordlists.saved[p.name] = str(p.resolve())
        cfg.wordlists.active = str(p.resolve())
        cm.save(cfg)
        print(f"Added and activated wordlist: {p}")
    if use:
        if use not in cfg.wordlists.saved:
            raise SystemExit(f"unknown saved wordlist key: {use}")
        cfg.wordlists.active = cfg.wordlists.saved[use]
        cm.save(cfg)
        print(f"Active wordlist: {cfg.wordlists.active}")
    if show:
        print(json.dumps(cfg.wordlists.saved, indent=2))
        print(f"active={cfg.wordlists.active}")
    return 0


def cmd_doctor() -> int:
    deps = ["john", "hashcat", "pdf2john", "zip2john", "rar2john", "office2john", "ssh2john"]
    print(AUTHORIZED_USE)
    print("Dependency\tStatus\tPath")
    for d in deps:
        path = which(d)
        print(f"{d}\t{'OK' if path else 'MISSING'}\t{path or '-'}")
    return 0


def cmd_crack(target: str, wordlist: str | None, backend: str, attack_mode: str, mask: str | None, rule: str | None) -> int:
    print(AUTHORIZED_USE)
    detector = InputDetector()
    detection = detector.detect(target)
    print(f"Detected: {detection.kind} ({detection.confidence:.2f}) - {detection.reason}")

    hash_value = None
    hash_file = None
    if detection.kind in {"pdf", "zip", "rar", "office", "7z", "ssh"}:
        extracted = JohnExtractorRegistry().extract(detection.kind, target)
        if not extracted.ok:
            raise SystemExit(f"Extraction failed: {extracted.error}")
        hash_value = extracted.hash_value
        hash_file = Path(f".smartcrack_{Path(target).name}.hash")
        hash_file.write_text(hash_value + "\n")
    elif detection.kind == "raw-hash":
        hash_value = target
        hash_file = Path(".smartcrack_input.hash")
        hash_file.write_text(hash_value + "\n")
    else:
        p = Path(target)
        if p.exists():
            hash_file = p
            hash_value = _read_hash_input(target)
        else:
            raise SystemExit("Unsupported input target")

    guesses = HashIdentifier().identify(hash_value)
    if not guesses:
        raise SystemExit("Could not identify hash")

    best = guesses[0]
    try:
        selected = BackendSelector().select(best.hashcat_mode, best.john_format, prefer=backend)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc

    cm = ConfigManager()
    cfg = cm.load()
    wl = wordlist or cfg.wordlists.active
    if attack_mode == "dictionary" and wl and not Path(wl).exists():
        raise SystemExit(f"Configured wordlist does not exist: {wl}")
    if attack_mode == "dictionary" and not wl:
        print("No active wordlist configured. Use: smartcrack wordlists --add /path/to/list.txt")

    for hint in recommend(detection.kind, best.algorithm):
        print(f"Hint: {hint}")

    result = CrackingEngine().run(selected.command, str(hash_file), wordlist=wl, attack_mode=attack_mode, mask=mask, rule=rule)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)

    sess = CrackSession(
        session_id=str(uuid.uuid4()),
        input_path=target,
        target_type=detection.kind,
        backend=selected.backend,
        command=selected.command,
        status="completed" if result.returncode == 0 else "failed",
    )
    SessionStore().save(sess)
    return result.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="smartcrack", description="SmartCrack: wrapper around Hashcat + John")
    sub = parser.add_subparsers(dest="command", required=True)

    p_ident = sub.add_parser("identify", help="Identify hash algorithm")
    p_ident.add_argument("input_value")

    p_words = sub.add_parser("wordlists", help="Manage wordlists")
    p_words.add_argument("--add")
    p_words.add_argument("--use")
    p_words.add_argument("--show", action="store_true")

    sub.add_parser("doctor", help="Check external dependencies and environment")

    p_crack = sub.add_parser("crack", help="Crack target")
    p_crack.add_argument("target")
    p_crack.add_argument("--wordlist")
    p_crack.add_argument("--backend", choices=["auto", "hashcat", "john"], default="auto")
    p_crack.add_argument("--attack-mode", choices=["dictionary", "mask"], default="dictionary")
    p_crack.add_argument("--mask", help="Mask pattern (for mask attack mode)")
    p_crack.add_argument("--rule", help="Hashcat/John rule file")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "identify":
        return cmd_identify(args.input_value)
    if args.command == "wordlists":
        return cmd_wordlists(args.add, args.use, args.show)
    if args.command == "doctor":
        return cmd_doctor()
    if args.command == "crack":
        return cmd_crack(args.target, args.wordlist, args.backend, args.attack_mode, args.mask, args.rule)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
