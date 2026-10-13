// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// Copyright (c) 2026 2351485 ALBERTA INC.

import { describe, expect, it } from "vitest";
import { originOfUrl } from "../src/origin.js";

describe("originOfUrl", () => {
  it("normalizes like the desktop host", () => {
    expect(originOfUrl("https://GitHub.com/login")).toBe("https://github.com");
    expect(originOfUrl("https://github.com:443/x")).toBe("https://github.com");
    expect(originOfUrl("http://example.com:80/")).toBe("http://example.com");
    expect(originOfUrl("https://secure.bank.example:8443/")).toBe(
      "https://secure.bank.example:8443",
    );
    expect(originOfUrl("https://example.com./")).toBe("https://example.com");
  });

  it("refuses non-web schemes and credential-bearing urls", () => {
    expect(originOfUrl("ftp://example.com/")).toBeNull();
    expect(originOfUrl("chrome://extensions")).toBeNull();
    expect(originOfUrl("file:///etc/passwd")).toBeNull();
    expect(originOfUrl("https://user:pass@example.com/")).toBeNull();
    expect(originOfUrl("not a url")).toBeNull();
    expect(originOfUrl("")).toBeNull();
  });
});
