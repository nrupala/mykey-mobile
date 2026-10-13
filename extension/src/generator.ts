// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Copyright (c) 2026 2351485 ALBERTA INC.

/** Password generation, mirroring the desktop generator
 * (mykey.py generate_password): same alphabet (letters + digits +
 * punctuation), unbiased selection. Generating needs no vault access,
 * so it lives locally; the desktop enforces the same 16-character
 * floor for anything it stores. */

export const MIN_GENERATED_PASSWORD_LENGTH = 16;

const ALPHABET =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
  "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

export function generatePassword(length = 20): string {
  if (length < MIN_GENERATED_PASSWORD_LENGTH) {
    throw new Error(
      `generated passwords must be at least ${MIN_GENERATED_PASSWORD_LENGTH} characters`,
    );
  }
  const out: string[] = [];
  const max = Math.floor(256 / ALPHABET.length) * ALPHABET.length;
  const buf = new Uint8Array(length * 2);
  while (out.length < length) {
    crypto.getRandomValues(buf);
    for (const byte of buf) {
      if (byte >= max) continue; // rejection sampling — no modulo bias
      out.push(ALPHABET[byte % ALPHABET.length] as string);
      if (out.length === length) break;
    }
  }
  return out.join("");
}
