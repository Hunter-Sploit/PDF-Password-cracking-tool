from __future__ import annotations
import uuid
from pathlib import Path
import typer
from rich import print
from rich.table import Table
from .config.manager import ConfigManager
from .config.models import CrackSession
from .crackers.backends import BackendSelector
from .crackers.engine import CrackingEngine
from .detectors.input_detector import InputDetector
from .extractors.john_extractors import JohnExtractorRegistry
from .identifiers.hash_identifier import HashIdentifier
from .recommender import recommend
from .sessions.store import SessionStore

app = typer.Typer(help="SmartCrack: intelligent wrapper around Hashcat + John")


@app.command()
def identify(input_value: str):
    """Identify likely hash algorithm(s) for a raw hash string or file containing hashes."""
    src = Path(input_value)
    data = src.read_text().strip().splitlines()[0] if src.exists() else input_value
    guesses = HashIdentifier().identify(data)
    table = Table(title="Identification Results")
    table.add_column("Algorithm")
    table.add_column("Hashcat Mode")
    table.add_column("John Format")
    table.add_column("Confidence")
    for g in guesses:
        table.add_row(g.algorithm, g.hashcat_mode, g.john_format, f"{g.confidence:.2f}")
    print(table)


@app.command()
def wordlists(add: str = typer.Option(None), use: str = typer.Option(None), show: bool = typer.Option(False)):
    cm = ConfigManager()
    cfg = cm.load()
    if add:
        p = Path(add)
        if not p.exists():
            raise typer.BadParameter(f"wordlist does not exist: {add}")
        cfg.wordlists.saved[p.name] = str(p.resolve())
        cfg.wordlists.active = str(p.resolve())
        cm.save(cfg)
        print(f"[green]Added and activated wordlist:[/green] {p}")
    if use:
        if use not in cfg.wordlists.saved:
            raise typer.BadParameter(f"unknown saved wordlist key: {use}")
        cfg.wordlists.active = cfg.wordlists.saved[use]
        cm.save(cfg)
        print(f"[green]Active wordlist:[/green] {cfg.wordlists.active}")
    if show:
        print(cfg.wordlists.saved)
        print(f"active={cfg.wordlists.active}")


@app.command()
def crack(target: str, wordlist: str = typer.Option(None), backend: str = typer.Option("auto")):
    detector = InputDetector()
    detection = detector.detect(target)
    print(f"[cyan]Detected[/cyan]: {detection.kind} ({detection.confidence:.2f}) - {detection.reason}")

    hash_value = None
    hash_file = None
    if detection.kind in {"pdf", "zip", "rar", "office", "7z", "ssh"}:
        extracted = JohnExtractorRegistry().extract(detection.kind, target)
        if not extracted.ok:
            raise typer.Exit(f"Extraction failed: {extracted.error}")
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
            hash_value = p.read_text().strip().splitlines()[0]
        else:
            raise typer.Exit("Unsupported input target")

    guesses = HashIdentifier().identify(hash_value)
    if not guesses:
        raise typer.Exit("Could not identify hash")
    best = guesses[0]
    selected = BackendSelector().select(best.hashcat_mode, best.john_format, prefer=backend)

    cm = ConfigManager()
    cfg = cm.load()
    wl = wordlist or cfg.wordlists.active
    if not wl:
        print("[yellow]No active wordlist configured. Use smartcrack wordlists --add /path/to/list.txt[/yellow]")

    for hint in recommend(detection.kind, best.algorithm):
        print(f"[magenta]Hint:[/magenta] {hint}")

    result = CrackingEngine().run(selected.command, str(hash_file), wordlist=wl)
    print(result.stdout)
    if result.stderr:
        print(f"[red]{result.stderr}[/red]")

    sess = CrackSession(session_id=str(uuid.uuid4()), input_path=target, target_type=detection.kind, backend=selected.backend, command=selected.command, status="completed" if result.returncode == 0 else "failed")
    SessionStore().save(sess)


def main():
    app()

if __name__ == "__main__":
    main()
