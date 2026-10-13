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
    # Licensing wave: a vault carrying a TEST licence in its
    # encrypted settings (tests/licence.test.ts opens it as
    # licensed). Guarded: fixture generation works against a
    # desktop checkout that predates the licensing module too —
    # the fixture is then skipped, and the TS test treats it as
    # optional for the same reason. The token is the shared
    # cross-client fixture: seed bytes(range(32)), fixed payload,
    # identical string in both repos' test suites. FAKE test
    # licence — the test authority, never the production one.
    try:
        import licensing as licensing_mod
    except ImportError:
        licensing_mod = None
    if licensing_mod is not None:
        import tempfile
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey)
        # Keep the device-local slot out of the runner's real home.
        licensing_mod.device_licence_path = lambda: os.path.join(
            tempfile.mkdtemp(prefix="mykey-fixture-"), "licence.key")
        test_priv = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        test_payload = {
            "licence_id": "lic-test000000000001",
            "licensee": "test-buyer@example.com",
            "product": "mykey",
            "edition": "unlimited",
            "issued_at": "2026-10-13T00:00:00Z",
            "payment_date": "2026-10-01",
            "serial": "0123456789abcdeffedcba9876543210",
            "passcode": licensing_mod.compute_passcode(
                "test-buyer@example.com", "2026-10-01", "1990-05-17",
                "0123456789abcdeffedcba9876543210"),
            "max_connections": 20,
        }
        test_token = licensing_mod.make_token(test_payload, test_priv)
        lic_path = os.path.join(OUT, "py-licensed.mykey")
        for suffix in ("", ".bak", ".audit.jsonl", ".audit-anchor.json"):
            try:
                os.unlink(lic_path + suffix)
            except OSError:
                pass
        lapp = MyKey("cross-client fixture 1", vault_file=lic_path)
        lapp.licence_public_key_b64 = (
            "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=")
        licensing_mod.activate_licence(lapp, test_token)
        lapp.add_entry(make_entry(service="fixture-service",
                                  username="user", password="fixture-pw"))
        for suffix in (".bak", ".audit.jsonl", ".audit-anchor.json"):
            try:
                os.unlink(lic_path + suffix)
            except OSError:
                pass
    # --- Passkey fixture (separate vault; the main fixture's entry
    # count is asserted exactly by existing tests, so passkeys get
    # their own file). Deterministic EC key, like the desktop tests.
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        Encoding, NoEncryption, PrivateFormat, PublicFormat)
    FIXED_SCALAR = 0x5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED
    priv = ec.derive_private_key(FIXED_SCALAR, ec.SECP256R1())
    pkcs8 = priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    point = priv.public_key().public_bytes(
        Encoding.X962, PublicFormat.UncompressedPoint)
    from mykey import _b64e as b64e
    pk_record = {
        "rp_id": "example.com",
        "user_id": b64e(b"fixture-user-01"),
        "user_name": "user@example.com",
        "user_display_name": "Fixture User",
        "credential_id": b64e(bytes(range(16))),
        "alg": -7,
        "public_key": b64e(point),
        "private_key": b64e(pkcs8),
        "sign_count": 7,
        "transports": ["internal"],
        "created_at": 1700000000,
        "aaguid": b64e(bytes(16)),
        "backup_eligible": True,
        "backed_up": True,
    }
    pk_path = os.path.join(OUT, "fixture-passkey.mykey")
    for suffix in ("", ".bak", ".audit.jsonl", ".audit-anchor.json"):
        try:
            os.unlink(pk_path + suffix)
        except OSError:
            pass
    pk_app = MyKey(PASSWORD, vault_file=pk_path)
    pk_app.unlock()
    pk_app.add_entry(make_entry(
        service="github", username="octocat", password="fake-gh-pass-123",
        url="https://github.com", notes="login beside the passkey",
        totp_secret="", tags=["dev"], favourite=False))
    pk_app.add_passkey(pk_record)
    for suffix in (".bak", ".audit.jsonl", ".audit-anchor.json",
                   ".backup-state.json"):
        try:
            os.unlink(pk_path + suffix)
        except OSError:
            pass
    expected["passkey"] = {
        "fixture_file": "fixture-passkey.mykey",
        "rp_id": "example.com",
        "user_name": "user@example.com",
        "credential_id": pk_record["credential_id"],
        "public_key": pk_record["public_key"],
        "sign_count": 7,
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
