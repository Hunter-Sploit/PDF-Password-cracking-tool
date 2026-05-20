# SmartCrack

> Authorized use only. Use only on systems/files you own or are explicitly authorized to test.

SmartCrack evolves this repository from a legacy PDF-only dictionary cracker into a modular framework that automates detection, extraction, identification, and cracking backend selection across common formats.

## Reuse of the original PDF cracker

The original script's strengths were:
- simple dictionary-first workflow
- local-only execution
- practical PDF target focus

Those workflows are preserved and generalized:
- PDF path now flows through detector -> `pdf2john` extractor -> identifier -> backend runner
- wordlist-first behavior remains the default strategy
- legacy entrypoint (`pdf_cracker.py`) still works as a compatibility launcher

## Install

### 1) Python setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) External tooling
Install as many of these as possible:
- `john` (jumbo build recommended for `*2john` extractors)
- `hashcat`

If one backend is missing, SmartCrack will automatically try the other when possible.

## Commands

```bash
python -m smartcrack identify '<hash>'
python -m smartcrack identify hashes.txt
python -m smartcrack wordlists --add /path/to/rockyou.txt
python -m smartcrack wordlists --show
python -m smartcrack doctor
python -m smartcrack crack secret.pdf
python -m smartcrack crack archive.zip --backend john
python -m smartcrack crack dump.hash --wordlist /path/to/wordlist.txt
```

Legacy compatibility:

```bash
python pdf_cracker.py crack secret.pdf
```

## Architecture

```text
smartcrack/
  cli.py                  # CLI orchestration
  detectors/              # file/hash target detection
  extractors/             # extractor wrappers (pdf2john, etc.)
  identifiers/            # hash identification + confidence
  crackers/               # backend selection + engine run
  config/                 # persisted app/wordlist configuration
  sessions/               # saved crack session metadata
  utils/                  # subprocess wrappers
  plugins/                # extension point
```

## Current limitations / next steps

- Add richer hash normalization and multi-line hash file support
- Add plugin registration interface
- Add benchmark mode and GPU capability profiling
- Add deeper John/Hashcat output parsers for live progress metrics


## Operational improvements in this revision

- Added `doctor` command to verify runtime dependencies before cracking.
- Added attack controls in `crack`: `--attack-mode dictionary|mask`, `--mask`, and `--rule`.
- Added stricter wordlist validation and clearer backend error handling.
