# SmartCrack

> Authorized use only. This tool is intended for legal security testing, incident response, and recovery workflows on assets you own or are explicitly authorized to assess.

SmartCrack is an intelligent Python framework that evolves the original PDF-only cracker into a modular automation layer over **Hashcat** and **John the Ripper**.

## What was reused from the old PDF tool

The original repo implemented a dictionary-based PDF cracking workflow using `pikepdf` and a wordlist loop. SmartCrack preserves that core workflow concept (wordlist-first attack, local-only execution) while upgrading architecture and automation:

- preserved dictionary-first cracking strategy
- preserved PDF-centric workflow by adding automatic `pdf2john` extraction
- preserved local/offline behavior
- replaced hardcoded file paths and broad exception handling with safe modular execution

## Features

- Smart input detection (magic bytes + heuristics)
- Automatic hash extraction via john helper tools (`pdf2john`, `zip2john`, `rar2john`, `office2john`, `ssh2john`, `7z2john.pl`)
- Hash identification with confidence score + hashcat/john mapping
- Automatic backend selection (Hashcat/John) with manual override
- Wordlist profile management with persistence
- Session save/history metadata
- Rich + Typer modern CLI UX
- Safety-first subprocess handling and explicit authorized-use warning

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Install external dependencies in your OS package manager:

- `hashcat`
- `john` (jumbo build preferred for extractor helpers)

## Usage

```bash
python -m smartcrack identify '$2b$12$.................................................'
python -m smartcrack identify hashes.txt
python -m smartcrack wordlists --add /path/to/rockyou.txt
python -m smartcrack crack secret.pdf
python -m smartcrack crack archive.zip --backend john
python -m smartcrack crack dump.hash --wordlist /path/to/wordlist.txt
```

Legacy command still works:

```bash
python pdf_cracker.py crack secret.pdf
```

## Project structure

```text
smartcrack/
  cli.py
  detectors/
  extractors/
  identifiers/
  crackers/
  sessions/
  config/
  utils/
  plugins/
```

## Next extensions

- plugin registration API for new target formats
- richer recommender with benchmark-driven scoring
- Textual dashboard mode
- distributed cracking orchestration
