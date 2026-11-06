# EntropyMint

Offline high-entropy credential forger.

**Built by Mourad.Soltani**

Generate cryptographically strong API keys, passwords, and tokens. Score any secret with Shannon entropy and weak-pattern detection. Pure Python stdlib — no dependencies, fully offline.

## Features

- CSPRNG-backed generation (`secrets` module)
- Multiple charsets: full, alnum, hex, base64, pin
- Shannon entropy scoring + theoretical max
- Weak pattern detection (sequential, repeats, dictionary words)
- JSON output for scripting and pipelines
- Health checks that must pass
- Zero network, zero installs beyond Python 3.9+

## Quick start

```bash
python3 src/entropymint.py generate -l 32 --json
python3 src/entropymint.py score "mysecret" --json
python3 src/entropymint.py health
```

## Requirements

- Python 3.9 or newer
- No third-party packages

## Buyer notes

You receive the complete source (`src/entropymint.py`), tests, and this README. Run immediately with `python3`. Ideal for developers who need reliable offline secret generation and scoring without external services.

License: MIT
