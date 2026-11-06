#!/usr/bin/env python3
"""Health and unit tests for EntropyMint. Built by Mourad.Soltani"""
import subprocess
import sys
import os

# Ensure we can import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from entropymint import generate_secret, score_secret, shannon_entropy, detect_weak_patterns


def test_generate_length():
    s = generate_secret(16, "alnum")
    assert len(s) == 16
    assert s.isalnum()


def test_entropy_high():
    s = generate_secret(40, "full")
    bits = shannon_entropy(s) * len(s)
    assert bits > 150


def test_score_weak():
    weak = "password123"
    score = score_secret(weak)
    assert "dictionary_word" in score["weak_patterns"] or score["grade"] in ("C", "F")


def test_health_cli():
    result = subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(__file__), "..", "src", "entropymint.py"), "health"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "health: ok" in result.stdout


if __name__ == "__main__":
    test_generate_length()
    test_entropy_high()
    test_score_weak()
    test_health_cli()
    print("All tests passed")
