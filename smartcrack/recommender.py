from __future__ import annotations

def recommend(target_type: str, identified_algo: str) -> list[str]:
    hints = []
    if target_type in {"pdf", "zip", "rar", "office"}:
        hints.append("Start with dictionary + best64.rule for document-based targets.")
    if identified_algo in {"ntlm", "md5", "sha1", "sha256"}:
        hints.append("Try mask attack for common patterns like ?u?l?l?l?l?d?d.")
    if identified_algo == "bcrypt":
        hints.append("Prefer focused wordlists/rules due to bcrypt computational cost.")
    if not hints:
        hints.append("Begin with dictionary attack, then escalate to hybrid and masks.")
    return hints
