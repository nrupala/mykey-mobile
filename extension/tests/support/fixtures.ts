// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// Copyright (c) 2026 2351485 ALBERTA INC.
//
// Fixture secrets for the extension test suites. These values are
// FAKE and exist only so leak tests can grep for them. They mirror
// the desktop fixture vault (tests/test_native_host.py) and the
// fixture builder (scripts/make_fixture_vault.py). Never real.

export const MASTER = "fixture-master-pass-13";

export const ENTRIES = [
  {
    id: "entry-github",
    service: "GitHub",
    username: "octocat",
    password: "FIXTURE-PW-ALPHA-123",
    url: "https://github.com",
    totp_secret: "JBSWY3DPEHPK3PXP",
  },
  {
    id: "entry-example",
    service: "Example",
    username: "subuser",
    password: "FIXTURE-PW-BETA-456",
    url: "https://example.com",
    totp_secret: "",
  },
  {
    id: "entry-bank",
    service: "Bank",
    username: "banker",
    password: "FIXTURE-PW-GAMMA-789",
    url: "https://secure.bank.example:8443",
    totp_secret: "",
  },
] as const;

/** Every fixture secret a leak test greps for. */
export const ALL_SECRETS: string[] = [
  MASTER,
  ...ENTRIES.map((e) => e.username),
  ...ENTRIES.map((e) => e.password),
  ...ENTRIES.map((e) => e.totp_secret).filter(Boolean),
];

export const GITHUB = ENTRIES[0];
export const EXAMPLE = ENTRIES[1];
export const BANK = ENTRIES[2];
