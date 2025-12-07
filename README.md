# sa015bcr Key Toolkit

Tools and reference implementations for reproducing the "GM 5-byte" key derivation flow documented in the SA015BCR platform. The project focuses on understanding how OEM password blobs are transformed into the short authentication keys used by service tools.

## Highlights

- Pure-Python reproduction of the proprietary AES-128 + SHA-256 pipeline (`keylib.py`).
- 0x00-0xFF password map extracted from OEM binaries for immediate testing.
- Command-line driver (`keygen.py`) that mirrors the original tool chain and exposes verbose tracing.
- PyQt5 front-end (`gui.py`) for quick manual key lookups.

## Repository Layout

| Path | Description |
| --- | --- |
| `keylib.py` | Core primitives: password map, blob parser, AES implementation, and derivation helpers. |
| `keygen.py` | CLI for deriving keys from a seed/algorithm pair or a custom blob. |
| `gui.py` | Lightweight PyQt5 GUI that wraps `derive_key_from_algo`. |

## Requirements

- Python 3.10+ (tested on Windows with `py` launcher).
- [PyQt5](https://pypi.org/project/PyQt5/) (for `gui.py`).

Install dependencies into your environment:

```powershell
py -m pip install --upgrade pip
py -m pip install PyQt5
```

## Usage

### 1. CLI Key Derivation (`keygen.py`)

```powershell
py keygen.py --seed 8CE7D1FD06 --algo 0x87 --verbose
```

- `--seed/ -s`: 5-byte seed as 10 hex digits (spaces/colons allowed).
- `--algo/ -a`: decimal or `0x` prefixed algorithm selector.
- `--password/ -p`: optional blob override if you sourced a new entry outside of `PASSWORD_MAP`.
- `--verbose/ -v`: print intermediate iteration count and AES key material.

The script prints the 5-byte key (`mac`) to stdout. On validation failures the argparse error mirrors the OEM behavior (seed bounds, missing blob, etc.).

### 2. GUI (`gui.py`)

```powershell
py gui.py
```

- Seed and algorithm inputs share the same validation logic as the CLI.
- Success and error states are shown inline, and the calculated key is copyable.
- The GUI is intentionally small so it can float above other diagnostic tools.

## How the Derivation Works

1. Each algo ID references a password blob (`PASSWORD_MAP`). The blob contains:
   - 32-byte secret, 2-byte `min_seed`, 2-byte `algo_id`, and an 8-byte SHA-256 digest.
2. The seed's fifth byte controls how many times the secret is iteratively hashed with SHA-256.
3. The derived digest is split into a 16-byte AES key, which encrypts a fixed block containing the seed.
4. The first 5 bytes of the AES output become the final key (`mac`).

`keylib.py` keeps these steps transparent so you can inspect or adapt each stage.

## Extending the Password Map

1. Gather encrypted blobs using your preferred extraction tooling (not included here).
2. Append them to `PASSWORD_MAP` with the correct `algo` numeric key.
3. Re-run `keygen.py` or the GUI to confirm the new mapping works.

Because the AES implementation is self-contained, you can also port `PASSWORD_MAP` and `derive_key_from_blob` into other projects (e.g., embedded tooling) without dragging in additional dependencies.

## Development Notes

- The repo does not include tests; when experimenting, prefer `keygen.py --verbose` to confirm intermediate steps.
- The AES/SHA code is intentionally explicit rather than optimized so researchers can audit each phase.
- Contributions are welcome via pull request—please document any new password sources or algorithm behaviors in this README.

## Disclaimer

This project is for research and interoperability. Use the tooling only with hardware and software you are authorized to service.
