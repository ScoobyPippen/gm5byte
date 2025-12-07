#!/usr/bin/env python3
"""CLI wrapper for the sa015bcr key-derivation utilities."""
from __future__ import annotations

import argparse
from typing import Sequence

from keylib import derive_key_from_algo, derive_key_from_blob


def parse_seed(text: str) -> bytes:
    """Normalize and validate a 5-byte seed from user input."""
    filtered = ''.join(ch for ch in text if ch not in ' ,:_')
    if len(filtered) != 10:
        raise argparse.ArgumentTypeError("Seed must be provided as 10 hex digits")
    try:
        return bytes.fromhex(filtered)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Seed is not valid hex") from exc


def parse_algo(text: str) -> int:
    """Parse decimal or hex algorithm numbers into an int."""
    try:
        value = int(text, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Algo must be an integer") from exc
    if not 0 <= value <= 0xFFFF:
        raise argparse.ArgumentTypeError("Algo must fit in 16 bits")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the CLI tool."""
    parser = argparse.ArgumentParser(description="Reproduce sa015bcr key derivation")
    parser.add_argument("--password", "-p",
                        help="Override password blob (defaults to library mapping by algo)")
    parser.add_argument("--seed", "-s", required=True, type=parse_seed,
                        help="5-byte seed expressed as 10 hex digits (spaces/colons allowed)")
    parser.add_argument("--algo", "-a", required=True, type=parse_algo,
                        help="Algorithm selector (decimal or 0x-prefixed hex)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show intermediate values")
    args = parser.parse_args(argv)

    try:
        if args.password:
            mac, iterations, aes_key = derive_key_from_blob(args.password, args.seed, args.algo)
        else:
            mac, iterations, aes_key = derive_key_from_algo(args.algo, args.seed)
    except ValueError as exc:
        parser.error(str(exc))

    if args.verbose:
        print(f"Iterations   : {iterations}")
        print(f"AES key      : {aes_key.hex()}")
        print(f"Seed (bytes) : {args.seed.hex()}")
    print(mac.hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
