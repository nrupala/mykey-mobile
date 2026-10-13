// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// Protocol vectors shared with the Python implementation: values
// below were produced by the Python oracle (recovery.py / argon2 /
// json.dumps) and by the official BIP-39 test vectors, and must be
// reproduced exactly by the TypeScript client.

import { describe, expect, it } from "vitest";
import {
  entropyToMnemonic,
  mnemonicToEntropy,
  mnemonicToSeedSync,
} from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { argon2idRaw } from "../src/vault/crypto.js";
import { canonicalJson, utf8Encode } from "../src/vault/encoding.js";
import { totpNow } from "../src/vault/totp.js";

describe("BIP-39 vectors (Python oracle + official vectors)", () => {
  it("entropy of zeroes is abandon x11 + about", () => {
    expect(entropyToMnemonic(new Uint8Array(16), wordlist)).toBe(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    expect(mnemonicToEntropy(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      wordlist,
    )).toEqual(new Uint8Array(16));
  });

  it("fixture phrase seed matches the Python implementation", () => {
    const seed = mnemonicToSeedSync(
      "legal winner thank year wave sausage worth useful legal winner thank yellow",
    );
    expect(Buffer.from(seed).toString("hex")).toBe(
      "878386efb78845b3355bd15ea4d39ef97d179cb712b77d5c12b6be415fffeffe" +
        "5f377ba02bf3f8544ab800b955e51fbff09828f682052a20faa6addbbddfb096",
    );
  });

  it("TREZOR passphrase vector matches the official BIP-39 vector", () => {
    const phrase = `${"abandon ".repeat(11)}about`;
    const seed = mnemonicToSeedSync(phrase, "TREZOR");
    expect(Buffer.from(seed).toString("hex")).toBe(
      "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e534955" +
        "31f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    );
  });
});

describe("Argon2id vector (Python argon2 oracle)", () => {
  it("matches the low-level argon2 reference output", async () => {
    const out = await argon2idRaw(utf8Encode("password"), utf8Encode("somesaltsomesalt"), {
      time_cost: 3,
      memory_cost: 4096,
      parallelism: 4,
    });
    expect(Buffer.from(out).toString("hex")).toBe(
      "caf28acc48c75a149b51051279ab7a77215fa3272ed53e4eff36a186662e18bc",
    );
  });
});

describe("Canonical JSON (Python json.dumps oracle)", () => {
  it("matches sort_keys + compact separators + ensure_ascii", () => {
    expect(canonicalJson({ b: 1, a: { z: [true, null, "é€"] } })).toBe(
      '{"a":{"z":[true,null,"\\u00e9\\u20ac"]},"b":1}',
    );
  });
});

describe("TOTP RFC 6238 values (Python totp.py oracle)", () => {
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  it("t=59 gives 287082", async () => {
    expect(await totpNow(secret, 59)).toBe("287082");
  });
  it("t=1111111109 gives 081804", async () => {
    expect(await totpNow(secret, 1111111109)).toBe("081804");
  });
  it("accepts an otpauth:// URL", async () => {
    const url = `otpauth://totp/GitHub:octocat?secret=${secret}&issuer=GitHub`;
    expect(await totpNow(url, 59)).toBe("287082");
  });
});
