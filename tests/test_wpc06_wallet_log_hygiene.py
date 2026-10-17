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

WPC-R17-01/R17-02 extension (2026-10-17): scan wallet_api_impl.cpp too and
pin the save-failure path: the save_wallet_file exception handler must log
filename + failure reason only -- it must never serialize the whole
wallet_data object (to_pretty_string(_wallet)), whose FC_REFLECT carries
blind_receipts[].data.blinding_factor (stealth_confirmation::memo_data,
confidential.hpp). WPC-R17-02: the transfer_to_blind-mate capture at
wallet.cpp (receive path tail) must not pass (confirm) to
FC_CAPTURE_AND_RETHROW: confirm.outputs[].decrypted_memo.blinding_factor
holds freshly generated blinds there.

R18 / R17I-01 hardening (2026-10-17): rx_confirm is now nesting-aware -- the
original `[^()]*` body could not match the multi-arg capture form
`FC_CAPTURE_AND_RETHROW( (a)(b)...(confirm) )` (0 matches against the exact
pre-fix 5a580663:wallet.cpp:1861) and the guard was vacuous. A two-sided
self-test in main() now fails the run (exit 2) if the pattern can no longer
flag the known pre-fix line or flags the fixed line.
"""

import pathlib
import re
import sys

WORKTREE = pathlib.Path(__file__).resolve().parent.parent
WALLET_CPP = WORKTREE / "libraries" / "wallet" / "wallet.cpp"
WALLET_IMPL_CPP = WORKTREE / "libraries" / "wallet" / "wallet_api_impl.cpp"

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


# Legitimate on the impl file: `string data = fc::json::to_pretty_string( _wallet );`
# feeding the on-disk file write (that is the save itself). The BAN is on any
# wallet-object serialization REACHING A LOG MACRO (the WaterHard-R17-01 save-
# failure handler used to wlog(to_pretty_string(_wallet)) directly), so the
# scan pairs "log macro present on the line" with wallet-object serialization
# markers, and separately pins the retired leak-line literal.
IMPL_LOG_RE = re.compile(r"\b(?:idump|wdump|ilog|dlog|elog|wlog)\s*\(")
IMPL_BANNED = (
    (re.compile(r"to_(?:pretty_string|variant_string)\s*\(\s*_wallet"),
     "wallet object serialized into a log line"),
    (re.compile(r"wallet file content is next"),
     "portion of the pre-WPC-R17-01 leak line"),
    (re.compile(r"blind_receipts"),
     "blind receipts on a log line carries memo blinding factors"),
)

# R17I-01 (round-18 audit): the original guard pattern could not match the
# nested multi-arg capture form `FC_CAPTURE_AND_RETHROW( (a)...(confirm) )`
# (0 matches against the pre-fix 5a580663:wallet.cpp:1861), so the regression
# check was vacuous for the actual leak. This pattern admits one level of
# nested paren groups on the way to the `(confirm)` token and is two-sided
# self-tested in main() so it cannot silently go vacuous again.
rx_confirm = re.compile(
    r"FC_CAPTURE_AND_RETHROW\s*\((?:[^()]*\([^()]*\))*[^()]*\(confirm\)"
    r"[^()]*\)")

# Two-sided non-vacuity self-test inputs: the exact pre-fix line (must be
# flagged) and the fixed line (must not be).
R17I01_PREFIX = ("} FC_CAPTURE_AND_RETHROW( (from_key_or_label)"
                 "(to_key_or_label)(amount_in)(symbol)(broadcast)(confirm) ) }")
R17I01_FIXED = ("} FC_CAPTURE_AND_RETHROW( (from_key_or_label)"
                "(to_key_or_label)(amount_in)(symbol)(broadcast) ) }")


def main():
    if not WALLET_CPP.is_file():
        print("FAIL: wallet.cpp not found at %s" % WALLET_CPP)
        return 2
    if not WALLET_IMPL_CPP.is_file():
        print("FAIL: wallet_api_impl.cpp not found at %s" % WALLET_IMPL_CPP)
        return 2
    # Guard self-test (R17I-01): fail closed if the (confirm) regression
    # regex ever becomes vacuous or over-broad again.
    if not rx_confirm.search(R17I01_PREFIX) or rx_confirm.search(R17I01_FIXED):
        print("FAIL: (confirm)-guard self-test failed - rx_confirm is vacuous "
              "or over-broad; fix the regex before trusting a PASS")
        return 2
    bare_res = [(n, bare_object_re(n)) for n in BARE_SECRET_OBJECTS]
    offenders = []
    # Pre-R17-02: the receive-path tail captured (confirm) here; the guard
    # now lives at module scope with its two-sided self-test (R17I-01).
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
        # WPC-R17-02: no exception capture of (confirm) anywhere in wallet.cpp
        # (fresh receipt blinds may not enter fc::exception serialization).
        f.seek(0)
        for lineno, line in enumerate(f, 1):
            if rx_confirm.search(line):
                offenders.append(
                    (lineno, "FC_CAPTURE(confirm): receipt blinds serialized "
                             "through exception detail", line.rstrip()))
    with open(WALLET_IMPL_CPP, "r", encoding="utf-8", errors="replace") as f:
        for lineno, line in enumerate(f, 1):
            if not IMPL_LOG_RE.search(line):
                continue
            for rx, why in IMPL_BANNED:
                if rx.search(line):
                    offenders.append(
                        (lineno, "impl:%s" % why, line.rstrip()))
                    break
    if offenders:
        print(
            "FAIL: %d secret-bearing wallet log line(s) in %s"
            % (len(offenders), WALLET_CPP)
        )
        for lineno, why, text in offenders:
            print("  line %d [%s]: %s" % (lineno, why, text.strip()))
        return 1
    print("PASS: no secret blinding material in wallet.cpp log lines; "
          "save-failure path logs filename only (wallet_api_impl.cpp); "
          "no (confirm) exception capture (WPC-R17-01/02)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
