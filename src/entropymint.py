#!/usr/bin/env python3
"""
EntropyMint — Offline high-entropy credential forger.
Built by Mourad.Soltani

Generates cryptographically strong secrets and scores them with Shannon entropy
plus weak-pattern detection. Pure stdlib. JSON-friendly for pipelines.
"""
from __future__ import annotations

import argparse
import json
import math
import secrets
import string
import sys
from collections import Counter
from typing import Dict, List, Optional

# Signature
__author__ = "Mourad.Soltani"
__version__ = "1.0.0"


CHARSETS = {
    "alnum": string.ascii_letters + string.digits,
    "alphanumeric": string.ascii_letters + string.digits,
    "full": string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?",
    "hex": string.hexdigits.lower(),
    "base64": string.ascii_letters + string.digits + "+/",
    "pin": string.digits,
}


def shannon_entropy(s: str) -> float:
    """Return Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def total_entropy_bits(s: str, charset_size: int) -> float:
    """Theoretical maximum entropy given charset."""
    if not s or charset_size <= 1:
        return 0.0
    return len(s) * math.log2(charset_size)


def detect_weak_patterns(s: str) -> List[str]:
    """Detect common weak patterns."""
    issues: List[str] = []
    if not s:
        return issues
    # Sequential
    for i in range(len(s) - 2):
        if ord(s[i + 1]) == ord(s[i]) + 1 and ord(s[i + 2]) == ord(s[i]) + 2:
            issues.append("sequential_chars")
            break
    # Repeated
    if any(s.count(c) > len(s) * 0.4 for c in set(s)):
        issues.append("high_repeat")
    # All same case or simple
    if s.isalpha() and (s.islower() or s.isupper()):
        issues.append("single_case")
    # Common words / dictionary-ish (simple)
    weak_words = {"password", "secret", "admin", "123456", "qwerty", "letmein"}
    if any(w in s.lower() for w in weak_words):
        issues.append("dictionary_word")
    return list(set(issues))


def generate_secret(length: int, charset: str, exclude_similar: bool = False) -> str:
    """Generate cryptographically strong secret using secrets module."""
    chars = CHARSETS.get(charset, CHARSETS["full"])
    if exclude_similar:
        similar = "0O1lI"
        chars = "".join(c for c in chars if c not in similar)
    if not chars:
        raise ValueError("Empty charset after filtering")
    return "".join(secrets.choice(chars) for _ in range(length))


def score_secret(secret: str, charset: str = "full") -> Dict:
    """Score an existing secret."""
    charset_size = len(CHARSETS.get(charset, CHARSETS["full"]))
    bits_per_char = shannon_entropy(secret)
    total_bits = bits_per_char * len(secret)
    theoretical = total_entropy_bits(secret, charset_size)
    issues = detect_weak_patterns(secret)
    grade = "A"
    if total_bits < 60 or issues:
        grade = "C"
    if total_bits < 40:
        grade = "F"
    elif total_bits < 80 and not issues:
        grade = "B"
    return {
        "secret_length": len(secret),
        "shannon_bits_per_char": round(bits_per_char, 3),
        "total_shannon_bits": round(total_bits, 1),
        "theoretical_max_bits": round(theoretical, 1),
        "charset": charset,
        "weak_patterns": issues,
        "grade": grade,
        "recommendation": "strong" if grade in ("A", "B") and not issues else "regenerate",
    }


def cmd_generate(args: argparse.Namespace) -> None:
    secret = generate_secret(args.length, args.charset, args.exclude_similar)
    result = score_secret(secret, args.charset)
    result["secret"] = secret
    result["mode"] = "generate"
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Secret: {secret}")
        print(f"Entropy: {result['total_shannon_bits']} bits  |  Grade: {result['grade']}")
        if result["weak_patterns"]:
            print(f"Warnings: {', '.join(result['weak_patterns'])}")


def cmd_score(args: argparse.Namespace) -> None:
    secret = args.secret or sys.stdin.read().strip()
    if not secret:
        print("No secret provided", file=sys.stderr)
        sys.exit(1)
    result = score_secret(secret, args.charset)
    result["mode"] = "score"
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(json.dumps(result, indent=2))


def cmd_health() -> None:
    """Basic health check that tests must pass."""
    # Generate and verify entropy floor
    s = generate_secret(32, "full")
    score = score_secret(s, "full")
    assert len(s) == 32
    assert score["total_shannon_bits"] > 100
    assert "sequential_chars" not in score["weak_patterns"]
    print("health: ok")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="EntropyMint — forge high-entropy secrets (Built by Mourad.Soltani)"
    )
    parser.add_argument("--version", action="version", version=f"EntropyMint {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="Generate a new secret")
    gen.add_argument("-l", "--length", type=int, default=32)
    gen.add_argument("-c", "--charset", choices=list(CHARSETS.keys()), default="full")
    gen.add_argument("--exclude-similar", action="store_true")
    gen.add_argument("--json", action="store_true")
    gen.set_defaults(func=cmd_generate)

    sco = sub.add_parser("score", help="Score an existing secret")
    sco.add_argument("secret", nargs="?", help="Secret to score (or stdin)")
    sco.add_argument("-c", "--charset", default="full")
    sco.add_argument("--json", action="store_true")
    sco.set_defaults(func=cmd_score)

    health = sub.add_parser("health", help="Run health checks")
    health.set_defaults(func=lambda a: cmd_health())

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
