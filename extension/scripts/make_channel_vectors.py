#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# Copyright (c) 2026 2351485 ALBERTA INC.

"""Generate the channel known-answer vectors from the PYTHON
implementation (the oracle). The TypeScript channel must reproduce
these bytes exactly; CI regenerates this file and fails on drift.

Usage: make_channel_vectors.py --desktop DIR --out FILE
The desktop dir is a checkout of nrupala/mykey (native_host.py).
"""

import argparse
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--desktop", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    sys.path.insert(0, os.path.abspath(args.desktop))

    import native_host
    from mykey import _b64e

    ext_priv = X25519PrivateKey.from_private_bytes(bytes([7] * 32))
    host_priv = X25519PrivateKey.from_private_bytes(bytes([9] * 32))
    ext_pub = ext_priv.public_key().public_bytes(Encoding.Raw,
                                                 PublicFormat.Raw)
    host_pub = host_priv.public_key().public_bytes(Encoding.Raw,
                                                   PublicFormat.Raw)
    client_nonce = bytes([1] * 32)
    server_nonce = bytes([2] * 32)
    shared = ext_priv.exchange(host_priv.public_key())
    keys = native_host.derive_session_keys(shared, client_nonce,
                                           server_nonce)
    import hashlib
    session_id = hashlib.sha256(client_nonce + server_nonce) \
        .hexdigest()[:32]

    def seal(direction, seq, message):
        nonce = native_host._nonce(direction, seq)
        ct = AESGCM(keys[direction]).encrypt(
            nonce, native_host._canonical(message),
            native_host._aad(direction, session_id, seq))
        return {"kind": "sealed", "session": session_id, "seq": seq,
                "nonce": _b64e(nonce), "ct": _b64e(ct)}

    messages_e2h = [
        {"kind": "unlock", "id": 1, "password": "fixture-master-pass-13"},
        {"kind": "match", "id": 2, "origin": "https://github.com"},
        {"kind": "fill", "id": 3, "entry_id": "abc123",
         "origin": "https://github.com"},
    ]
    messages_h2e = [
        {"kind": "hello_ack", "protocol": "mykey-ext-v1",
         "unlocked": False, "vault_configured": True,
         "scopes": ["fill", "save"]},
        {"kind": "result", "id": 2, "ok": True,
         "matches": [{"id": "abc123", "service": "GitHub",
                      "username": "octocat", "has_totp": True,
                      "fill_subdomains": False}]},
    ]
    vectors = {
        "ext_priv_b64": _b64e(ext_priv.private_bytes(
            Encoding.Raw,
            __import__("cryptography.hazmat.primitives.serialization",
                       fromlist=["PrivateFormat"]).PrivateFormat.Raw,
            __import__("cryptography.hazmat.primitives.serialization",
                       fromlist=["NoEncryption"]).NoEncryption())),
        "ext_pub_b64": _b64e(ext_pub),
        "host_pub_b64": _b64e(host_pub),
        "client_nonce_b64": _b64e(client_nonce),
        "server_nonce_b64": _b64e(server_nonce),
        "session_id": session_id,
        "keys": {d: keys[d].hex() for d in keys},
        "e2h": [{"message": m, "frame": seal("e2h", i, m)}
                for i, m in enumerate(messages_e2h)],
        "h2e": [{"message": m, "frame": seal("h2e", i, m)}
                for i, m in enumerate(messages_h2e)],
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(vectors, f, indent=1)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
