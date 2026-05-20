"""Legacy compatibility launcher.

This file keeps the original entry point but routes execution to SmartCrack.
"""

from smartcrack.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
