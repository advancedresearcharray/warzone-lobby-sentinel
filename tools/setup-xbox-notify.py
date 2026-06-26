#!/usr/bin/env python3
"""One-time Xbox Live auth so Warzone Sentinel can toast your console."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel.xbox_notify import (
    _token_path,
    authorize_url,
    exchange_auth_code,
    notify_session_alert,
    save_tokens,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Xbox notification OAuth setup")
    parser.add_argument(
        "--code",
        help="Authorization code or full redirect URL after Microsoft sign-in",
    )
    parser.add_argument("--url-only", action="store_true", help="Print sign-in URL and exit")
    args = parser.parse_args()

    url = authorize_url()
    if args.url_only:
        print(url)
        return 0

    code = args.code or os.environ.get("WZ_XBOX_AUTH_CODE", "").strip()
    if not code:
        print("Xbox notification setup — sign in with the Microsoft account on your Xbox.")
        print("Open this URL in a browser, sign in, then paste the full redirect URL:\n")
        print(url)
        print()
        try:
            code = input("Paste redirect URL (or code): ").strip()
        except EOFError:
            print("\nNo input — re-run with --code or WZ_XBOX_AUTH_CODE.", file=sys.stderr)
            return 1

    if not code:
        print("No code provided.", file=sys.stderr)
        return 1

    try:
        tok = exchange_auth_code(code)
    except Exception as exc:
        print(f"OAuth failed: {exc}", file=sys.stderr)
        return 1

    save_tokens(tok)
    print(f"\nSaved to {_token_path()}")
    print("Sending test notification to your Xbox...")

    notify_session_alert(
        "TEST",
        50,
        "matchmaking",
        "Warzone",
        "Setup complete — you will get alerts like this when lobby risk is high.",
        ["Test notification"],
        force=True,
    )
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
