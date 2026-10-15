#!/usr/bin/env python3
"""WPC-06 regression test: wallet must never log secret blinding material.

TDD RED (2026-10-15): FAILS while libraries/wallet/wallet.cpp passes a
blinding scalar (blind_factor / to_blind_factor / change_blind_factor /
blinding_factor) -- or dumps a whole operation object that carries one
(e.g. transfer_from_blind_operation::blinding_factor, confidential.hpp)
-- to an fc log macro (idump/wdump/ilog/dlog/elog).

Usage:  python3 tests/test_wpc06_wallet_log_hygiene.py
Exit 0 = no secret-bearing log line. Exit 1 = leak present (prints lines).

Deliberately loggable (public on-chain or non-secret): commitments,
assets/amounts, account names/ids, tx ids, redacted markers.

Limitation: single-line scan -- every secret-bearing log invocation in
wallet.cpp to date is single-line; a multi-line idump( ... ) spreading a
secret token across lines would evade this. Keep log invocations one line.
"""

import pathlib
import re
import sys

WORKTREE = pathlib.Path(__file__).resolve().parent.parent
WALLET_CPP = WORKTREE / "libraries" / "wallet" / "wallet.cpp"

LOG_MACRO_RE = re.compile(r"\b(idump|wdump|ilog|dlog|elog)\s*\(")

# Secret scalar identifiers that must never appear inside a log invocation.
# "blind_factor" as substring also covers to_blind_factor /
# change_blind_factor / to_sum_blind_factor.
SECRET_TOKENS = (
    "blind_factor",
    "blinding_factor",
    "get_secret",  # one_time_key.get_secret() -- raw private scalar
    "shared_secret",  # ECDH secret (defense in depth; currently unlogged)
    "nonce",  # range-proof nonces (defense in depth; currently unlogged)
)

# Whole objects whose fc-reflected dump carries a blinding_factor field, so
# they must never be passed BARE to a log macro. Field projections
# (e.g. (from_blind.fee)) are fine; only the bare (from_blind) dump leaks.
#   from_blind : transfer_from_blind_operation (confidential.hpp) -- set from
#   decrypted_memo.blinding_factor BEFORE the log site.
BARE_SECRET_OBJECTS = ("from_blind",)


def bare_object_re(name):
    return re.compile(r"\(\s*" + re.escape(name) + r"\s*\)")


def main():
    if not WALLET_CPP.is_file():
        print("FAIL: wallet.cpp not found at %s" % WALLET_CPP)
        return 2
    bare_res = [(n, bare_object_re(n)) for n in BARE_SECRET_OBJECTS]
    offenders = []
    with open(WALLET_CPP, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            if not LOG_MACRO_RE.search(line):
                continue
            lowered = line.lower()
            for tok in SECRET_TOKENS:
                if tok in lowered:
                    offenders.append((lineno, "token:%s" % tok, line.rstrip()))
                    break
            else:
                for name, rx in bare_res:
                    if rx.search(line):
                        offenders.append(
                            (lineno, "bare-object:%s" % name, line.rstrip())
                        )
                        break
    if offenders:
        print(
            "FAIL: %d secret-bearing wallet log line(s) in %s"
            % (len(offenders), WALLET_CPP)
        )
        for lineno, why, text in offenders:
            print("  line %d [%s]: %s" % (lineno, why, text.strip()))
        return 1
    print("PASS: no secret blinding material in wallet.cpp log lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
