"""Legacy compatibility launcher.

This file keeps the original entry point but routes execution to SmartCrack.
"""

from smartcrack.cli import app

if __name__ == "__main__":
    app(prog_name="smartcrack")
