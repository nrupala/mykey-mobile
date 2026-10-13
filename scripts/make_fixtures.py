#!/usr/bin/env python3
# Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
# Test tooling: generates interoperability fixtures with the Python
# implementation (the oracle). All credentials below are FAKE test
# values, published deliberately so the TypeScript client can be
# tested against them. Never use them anywhere else.
"""Generate tests/fixtures/* using the Python MyKey implementation.

Usage:  MYKEY_PY_DIR=/path/to/mykey python3 scripts/make_fixtures.py
MYKEY_PY_DIR defaults to ../mykey (a checkout of nrupala/mykey main).
Requires the Python implementation's deps (cryptography, argon2-cffi).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "tests", "fixtures")
PY_DIR = os.environ.get("MYKEY_PY_DIR", os.path.join(HERE, "..", "..", "mykey"))
sys.path.insert(0, os.path.abspath(PY_DIR))

from mykey import MyKey, make_entry          # noqa: E402
import recovery                               # noqa: E402
import devices                                # noqa: E402
import pairings                               # noqa: E402
from backup_pkg import export_package         # noqa: E402
from totp import totp_now                     # noqa: E402

PASSWORD = "Correct-Horse-2026!"              # fake, test-only
# The phrase is the published BIP-39 test-vector mnemonic for entropy
# 0x7f*16 — computed from the entropy here so it can never drift from
# the standard. A public test value, not a real secret.
PHRASE = recovery.entropy_to_mnemonic(bytes([0x7F] * 16))
assert recovery.validate_mnemonic(PHRASE)
TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # ASCII "12345678901234567890"

ENTRIES = [
    dict(service="github", username="octocat", password="fake-gh-pass-123",
         url="https://github.com", notes="fake entry for interop tests",
         totp_secret=TOTP_SECRET, tags=["dev"], favourite=True),
    dict(service="bank", username="joint", password="fake-bank-pass-456",
         url="https://bank.example", notes="", totp_secret="",
         tags=["finance"], favourite=False),
    dict(service="email", username="user@example.com",
         password="fake-mail-pass-789", url="", notes="no totp here",
         totp_secret="", tags=[], favourite=False),
]


def main():
    os.makedirs(OUT, exist_ok=True)
    vault_path = os.path.join(OUT, "fixture.mykey")
    for suffix in ("", ".bak", ".audit.jsonl", ".audit-anchor.json"):
        try:
            os.unlink(vault_path + suffix)
        except OSError:
            pass
    app = MyKey(PASSWORD, vault_file=vault_path)
    app.unlock()  # creates a fresh Vault v3 vault
    for e in ENTRIES:
        app.add_entry(make_entry(**e))
    # Fixed-phrase recovery slot + Phase 3A backup recovery recipient,
    # set exactly the way setup_recovery does, but with the public
    # test phrase so the TS client can exercise the same paths.
    salt = os.urandom(16)
    wrapping = recovery.derive_recovery_key(PHRASE, salt)
    _raw, pub = recovery.recovery_backup_keypair(PHRASE, app._vault_id)
    app._backup_recovery_pub = pub
    from mykey import _ARGON, _b64e
    slot = app._make_slot("recovery", wrapping,
                          {"salt": _b64e(salt), **_ARGON})
    app._slots = [s for s in app._slots if s.get("id") != "recovery"] + [slot]
    app._persist()

    # An enrolled agent with list + get:github scopes, so the TS
    # client's bundle rebuild on save can be cross-checked: after a
    # TS save, this token must still open its bundle and read the
    # github entry — and must NOT be able to read the bank entry.
    import agents as agents_mod
    token = agents_mod.enroll_agent(app, "fixture-agent",
                                    ["list", "get:github"])

    # A device identity + MKBAK packages. Since the blob wave the
    # default package is v2: recovery is TWO-FACTOR (phrase + the
    # backup code returned here — a test value in expected.json),
    # and paired targets holding the export scope get a slot.
    ident = devices.DeviceIdentity.generate("fixture-device")
    devices.enroll_device(app, ident.card())
    target = pairings.PairingTargetIdentity.generate(
        "export", "fixture-target")
    pairings.enroll_pairing(app, target.payload(),
                            ["push", "pull", "export"])
    pkg_path = os.path.join(OUT, "fixture.mykeybak")
    _pkg, backup_code = export_package(app, ident, out_path=pkg_path)
    assert backup_code, "v2 export must yield a backup code"
    # Legacy v1 package (phrase-only recovery) for the downgrade-
    # labelled import path.
    legacy_path = os.path.join(OUT, "fixture-v1.mykeybak")
    export_package(app, ident, out_path=legacy_path, version=1)
    # After revocation the same export must carry NO pairing slot.
    pairings.revoke_pairing(app, target.target_id)
    nopair_path = os.path.join(OUT, "fixture-nopair.mykeybak")
    export_package(app, ident, out_path=nopair_path)

    expected = {
        "password": PASSWORD,
        "phrase": PHRASE,
        "vault_id": app._vault_id,
        "entries": [
            {k: e[k] for k in ("service", "username", "password", "url",
                               "notes", "totp_secret", "tags", "favourite")}
            for e in ENTRIES
        ],
        "totp": {
            "secret": TOTP_SECRET,
            "at_59": totp_now(TOTP_SECRET, at=59),      # RFC 6238 t=59
            "at_1111111109": totp_now(TOTP_SECRET, at=1111111109),
        },
        "backup": {
            "source_fingerprint": ident.fingerprint,
            "package_file": "fixture.mykeybak",
            # The v2 fixture package's backup code (test-only value,
            # like everything in this file).
            "backup_code": backup_code,
            "legacy_file": "fixture-v1.mykeybak",
        },
        "pairing": {
            "target_id": target.target_id,
            "fingerprint": target.fingerprint,
            # Test-only private key: lets the TS client exercise the
            # pairing import path against fixture.mykeybak.
            "priv_b64": __import__("base64").b64encode(
                target.x_priv_raw).decode(),
            "revoked_package_file": "fixture-nopair.mykeybak",
        },
        "agent": {"id": "fixture-agent", "token": token,
                  "scopes": ["list", "get:github"]},
    }
    # Remove Python sidecar/backup files so the fixtures directory
    # ships exactly the artefacts the tests consume.
    for suffix in (".bak", ".audit.jsonl", ".audit-anchor.json",
                   ".backup-state.json"):
        try:
            os.unlink(vault_path + suffix)
        except OSError:
            pass
    with open(os.path.join(OUT, "expected.json"), "w", encoding="utf-8") as f:
        json.dump(expected, f, indent=1)
    print("fixtures written to", OUT)


if __name__ == "__main__":
    main()
