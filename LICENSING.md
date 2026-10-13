# Licensing — Apache 2.0 interface layer + Proprietary core

This repository (MyKey web client + Android app) follows the same
licence split as the desktop engine (`nrupala/mykey`, see its
`LICENSING.md`): the interface layer is Apache 2.0; the vault-format
and cryptography core is proprietary.

| Bucket | Files | Terms |
|---|---|---|
| **Core — Proprietary** | `src/vault/vault.ts` (Vault v3 engine), `src/vault/crypto.ts`, `src/vault/encoding.ts`, `src/vault/recovery.ts`, `src/vault/totp.ts`, `src/vault/backup.ts` (MKBAK import) | © 2026 2351485 ALBERTA INC., all rights reserved. No licence is granted to copy, modify, or redistribute. **No patent licence is granted, express or implied; all patent rights are expressly reserved.** |
| **Interface layer — Apache 2.0** | `src/brand.ts`, `src/ui/**`, `src/platform/**`, `src/vault/store.ts`, `src/main.ts`, `src/styles.css`, `capacitor.config.ts`, `index.html`, `public/**`, the `android/` scaffolding, build/test configuration | Apache License 2.0 (full text in `LICENSES/Apache-2.0.txt`), including its §3 patent grant, scoped to this layer. |
| **Tests & scripts** | `tests/**`, `e2e/**`, `scripts/**` | Follow the bucket of the code they exercise: interop/vector material is proprietary-core; UI/config tests are Apache 2.0. Each file's header says which. |

Every source file carries its bucket's header. Product terms
(pricing, liability, venue) live in `TERMS.md` and are separate from
code licensing.

Owned by [Nrupal Akolkar](https://nrupalakolkar.com) · Built with
[Muse by Meta](https://muse.ai/join) — join Muse, then redeem code
**101EEK** in Settings within 48 hours of joining and we both earn
tokens.
