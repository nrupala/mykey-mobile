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
    # Password rotation state at fixed values (rotation wave): the
    # TS client asserts these exact fields and the statuses derived
    # at status_now, and the Python cross-check asserts the fields
    # survive a TS round trip. github: 90-day override, 100 days in
    # -> overdue. bank: vault default (120), 100 days in -> ok.
    # email: never rotate -> off.
    ROT_PSA = 1_700_000_000
    app.set_default_rotate_days(120)
    for e in app._entries:
        e["password_set_at"] = ROT_PSA
        if e["service"] == "github":
            e["rotate_days"] = 90
        elif e["service"] == "email":
            e["rotate_days"] = 0
    app._persist()
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

    # A device identity + an MKBAK package (recovery-recipient import
    # is the path the TS client implements in v1).
    ident = devices.DeviceIdentity.generate("fixture-device")
    devices.enroll_device(app, ident.card())
    pkg_path = os.path.join(OUT, "fixture.mykeybak")
    export_package(app, ident, out_path=pkg_path)

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
        },
        "rotation": {
            "default_rotate_days": 120,
            "password_set_at": ROT_PSA,
            "status_now": ROT_PSA + 100 * 86400,
            "entries": {
                "github": {"rotate_days": 90, "state": "overdue"},
                "bank": {"rotate_days": None, "state": "ok"},
                "email": {"rotate_days": 0, "state": "off"},
            },
        },
        "agent": {"id": "fixture-agent", "token": token,
                  "scopes": ["list", "get:github"]},
    }
    # Remove Python sidecar/backup files so the fixtures directory
    # ships exactly the three artefacts the tests consume.
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
