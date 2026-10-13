#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# Copyright (c) 2026 2351485 ALBERTA INC.

"""Build the fixture world for the host-integration + leak tests:
a fixture vault (fixture secrets ONLY — never a real vault), a host
store with one enrolled extension pairing, and a JSON config the
TypeScript tests read.

Usage: make_fixture_vault.py --desktop DIR --out DIR
"""

import argparse
import json
import os
import sys

MASTER = "fixture-master-pass-13"
EXT_ID = "abcdefghijklmnopabcdefghijklmnop"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--desktop", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    sys.path.insert(0, os.path.abspath(args.desktop))
    os.makedirs(args.out, exist_ok=True)

    import extpair
    from mykey import MyKey, _b64e, make_entry

    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    vault_path = os.path.join(args.out, "vault.mykey")
    vault = MyKey(MASTER, vault_file=vault_path)
    vault.unlock()
    vault.add_entry(make_entry(
        service="GitHub", username="octocat",
        password="FIXTURE-PW-ALPHA-123", url="https://github.com",
        totp_secret="JBSWY3DPEHPK3PXP"))
    vault.add_entry(make_entry(
        service="Example", username="subuser",
        password="FIXTURE-PW-BETA-456", url="https://example.com"))
    vault.add_entry(make_entry(
        service="Bank", username="banker",
        password="FIXTURE-PW-GAMMA-789",
        url="https://secure.bank.example:8443"))

    store_path = os.path.join(args.out, "extension-host.json")
    store = extpair.ExtensionHostStore.load(store_path)
    store.set_setting("vault_file", vault_path)

    ext_priv = X25519PrivateKey.generate()
    ext_pub = ext_priv.public_key().public_bytes(Encoding.Raw,
                                                 PublicFormat.Raw)
    payload = {
        "format": "MKEXTPAIR", "version": 1, "extension_id": EXT_ID,
        "label": "Integration Test Browser",
        "x25519_pub": _b64e(ext_pub),
        "fingerprint": extpair.extension_fingerprint(ext_pub),
    }
    store.enroll(payload, ["fill", "save"])

    config = {
        "master": MASTER,
        "vault": vault_path,
        "store": store_path,
        "extension_id": EXT_ID,
        "ext_priv_b64": _b64e(ext_priv.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
        "host_pub_b64": _b64e(store.host_public_key),
        "host_fingerprint": store.host_fingerprint,
    }
    config_path = os.path.join(args.out, "config.json")
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=1)
    print(config_path)


if __name__ == "__main__":
    main()
