// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// Passkey authenticator tests: creation stores a credential under
// its own vault key class, assertions are spec-shaped and verify
// against the stored public key, RP mismatches are refused, and
// sign_count is monotonic with a local clone-regression warning.

import { describe, expect, it } from "vitest";
import { sha256 } from "@noble/hashes/sha2.js";
import { b64decode, b64encode, utf8Encode } from "../src/vault/encoding.js";
import { VaultSession } from "../src/vault/vault.js";
import {
  NoCredentialError,
  RpIdMismatchError,
  b64urlDecode,
  b64urlEncode,
  checkCloneRegression,
  createCredential,
  getAssertion,
  p1363ToDer,
  updateHighWater,
} from "../src/vault/passkey.js";

const PASSWORD = "Passkey-Test-Password-1";
const CHALLENGE = b64urlEncode(new Uint8Array(32).fill(7));

function createOptions(rpId = "example.com") {
  return {
    challenge: CHALLENGE,
    rp: { id: rpId, name: "Example" },
    user: {
      id: b64urlEncode(utf8Encode("fixture-user-01")),
      name: "user@example.com",
      displayName: "Fixture User",
    },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
    attestation: "none",
  };
}

function getOptions(rpId = "example.com") {
  return { challenge: CHALLENGE, rpId, userVerification: "required" };
}

async function vaultWithPasskey(origin = "https://example.com", rpId = "example.com") {
  const s = await VaultSession.createNew(PASSWORD);
  const res = await createCredential(s, {
    origin,
    optionsJson: createOptions(rpId),
    userVerified: true,
  });
  return { s, res };
}

function derToP1363(der: Uint8Array): Uint8Array {
  // Minimal DER ECDSA-Sig-Value decode for verification in tests.
  let i = 2;
  if (der[1]! & 0x80) i += der[1]! & 0x7f;
  const readInt = (): Uint8Array => {
    const len = der[i + 1]!;
    let v = der.subarray(i + 2, i + 2 + len);
    i += 2 + len;
    while (v.length > 32) v = v.subarray(1);
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = readInt();
  const sPart = readInt();
  const out = new Uint8Array(64);
  out.set(r, 0);
  out.set(sPart, 32);
  return out;
}

describe("passkey creation", () => {
  it("stores a credential and returns a spec-shaped attestation", async () => {
    const { s, res } = await vaultWithPasskey();
    expect(res.type).toBe("public-key");
    expect(res.response.publicKeyAlgorithm).toBe(-7);
    const keys = s.listPasskeys();
    expect(keys).toHaveLength(1);
    const rec = keys[0]!.passkey!;
    expect(rec.rp_id).toBe("example.com");
    expect(rec.user_name).toBe("user@example.com");
    expect(rec.sign_count).toBe(0);
    expect(rec.alg).toBe(-7);
    // attestationObject is CBOR with fmt "none" — first bytes carry it
    const att = b64urlDecode(res.response.attestationObject);
    expect(new TextDecoder().decode(att.subarray(0, 24))).toContain("none");
    // authData inside starts with SHA256(rpId)
    expect(s.listEntries()).toHaveLength(1); // counts as an ordinary entry (free-cap seam)
  });

  it("refuses creation without user verification", async () => {
    const s = await VaultSession.createNew(PASSWORD);
    await expect(
      createCredential(s, { origin: "https://example.com", optionsJson: createOptions(), userVerified: false }),
    ).rejects.toThrow(/user verification/);
  });
});

describe("RP ID verification (the phishing defence)", () => {
  it("refuses a suffix-lookalike rpId", async () => {
    const s = await VaultSession.createNew(PASSWORD);
    await expect(
      createCredential(s, { origin: "https://example.com", optionsJson: createOptions("ample.com"), userVerified: true }),
    ).rejects.toBeInstanceOf(RpIdMismatchError);
  });

  it("refuses an unrelated rpId", async () => {
    const s = await VaultSession.createNew(PASSWORD);
    await expect(
      createCredential(s, { origin: "https://example.com", optionsJson: createOptions("other.com"), userVerified: true }),
    ).rejects.toBeInstanceOf(RpIdMismatchError);
  });

  it("refuses a lookalike host for assertions", async () => {
    const { s } = await vaultWithPasskey();
    await expect(
      getAssertion(s, { origin: "https://evil-example.com", optionsJson: getOptions("example.com"), userVerified: true }),
    ).rejects.toBeInstanceOf(RpIdMismatchError);
  });

  it("allows a subdomain origin under the rpId", async () => {
    const { s } = await vaultWithPasskey("https://login.example.com", "example.com");
    const a = await getAssertion(s, {
      origin: "https://login.example.com",
      optionsJson: getOptions("example.com"),
      userVerified: true,
    });
    expect(a.type).toBe("public-key");
  });
});

describe("assertions", () => {
  it("signature verifies against the stored public key; rpIdHash and counts are right", async () => {
    const { s } = await vaultWithPasskey();
    const recBefore = s.listPasskeys()[0]!.passkey!;
    for (let expected = 1; expected <= 2; expected++) {
      const a = await getAssertion(s, {
        origin: "https://example.com",
        optionsJson: getOptions(),
        userVerified: true,
      });
      const authData = b64urlDecode(a.response.authenticatorData);
      const rpHash = authData.subarray(0, 32);
      expect(Buffer.from(rpHash).equals(Buffer.from(sha256(utf8Encode("example.com"))))).toBe(true);
      const count = authData[33]! * 0x1000000 + authData[34]! * 0x10000 + authData[35]! * 0x100 + authData[36]!;
      expect(count).toBe(expected);
      const clientData = b64urlDecode(a.response.clientDataJSON);
      const clientHash = sha256(clientData);
      const signed = new Uint8Array(authData.length + clientHash.length);
      signed.set(authData, 0);
      signed.set(clientHash, authData.length);
      const pubRaw = b64decode(recBefore.public_key);
      const jwk = {
        kty: "EC",
        crv: "P-256",
        x: b64urlEncode(pubRaw.subarray(1, 33)),
        y: b64urlEncode(pubRaw.subarray(33, 65)),
      };
      const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      const der = b64urlDecode(a.response.signature);
      const ok = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        derToP1363(der) as BufferSource,
        signed as BufferSource,
      );
      expect(ok).toBe(true);
      // userHandle returns the stored user id
      expect(Buffer.from(b64urlDecode(a.response.userHandle)).toString()).toBe("fixture-user-01");
    }
    expect(s.listPasskeys()[0]!.passkey!.sign_count).toBe(2);
    // monotonic guard at the vault layer
    const entry = s.listPasskeys()[0]!;
    expect(() => s.updatePasskeySignCount(entry.id, 1)).toThrow(/backwards/);
  });

  it("no credential for an unstored rpId", async () => {
    const { s } = await vaultWithPasskey();
    await expect(
      getAssertion(s, { origin: "https://other.com", optionsJson: getOptions("other.com"), userVerified: true }),
    ).rejects.toBeInstanceOf(NoCredentialError);
  });

  it("sign_count persists across serialize/reopen", async () => {
    const { s } = await vaultWithPasskey();
    await getAssertion(s, { origin: "https://example.com", optionsJson: getOptions(), userVerified: true });
    const bytes = await s.serialize();
    const again = await VaultSession.openWithPassword(bytes, PASSWORD);
    expect(again.listPasskeys()[0]!.passkey!.sign_count).toBe(1);
    // the private key is nowhere in the serialized file as plaintext
    const rec = again.listPasskeys()[0]!.passkey!;
    expect(Buffer.from(bytes).toString("utf8")).not.toContain(rec.private_key);
    expect(Buffer.from(bytes).toString("utf8")).not.toContain(rec.credential_id);
  });
});

describe("clone detection (high-water marks)", () => {
  it("flags a regressed sign_count and updates the high-water mark", async () => {
    const { s } = await vaultWithPasskey();
    await getAssertion(s, { origin: "https://example.com", optionsJson: getOptions(), userVerified: true });
    await getAssertion(s, { origin: "https://example.com", optionsJson: getOptions(), userVerified: true });
    const records = s.listPasskeys().map((e) => e.passkey!);
    const hw = updateHighWater(records, {});
    expect(hw[records[0]!.credential_id]).toBe(2);
    const regressed = [{ ...records[0]!, sign_count: 1 }];
    const warnings = checkCloneRegression(regressed, hw);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]!.high_water).toBe(2);
    expect(checkCloneRegression(records, hw)).toHaveLength(0);
  });

  it("P1363→DER conversion round-trips a high-bit integer", () => {
    const p1363 = new Uint8Array(64);
    p1363[0] = 0xff;
    p1363[32] = 0x01;
    const der = p1363ToDer(p1363);
    expect(der[0]).toBe(0x30);
    // r needs a 0x00 prefix (33 bytes), s is 32 bytes after zero-strip
    expect(derToP1363(der)).toEqual(p1363);
    expect(b64encode(new Uint8Array([1]))).toBe("AQ==");
  });
});
