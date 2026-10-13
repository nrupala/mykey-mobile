// @vitest-environment jsdom
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

/** Help / FAQ / About guards (owner directive, 2026-10-13).

 * The text in src/content/ is a byte-for-byte mirror of the
 * canonical HELP.md / FAQ.md in the desktop repo — CI compares
 * the bytes. These tests pin what the text must contain, what it
 * must never claim (the parked Private vault; purchase content
 * while the free-tier question is unruled), the offline rule
 * (no web links in the body), and that the renderer builds DOM
 * without ever touching innerHTML. */

import { describe, expect, it } from "vitest";

import { aboutInfo, FAQ_MARKDOWN, HELP_MARKDOWN } from "../src/ui/help.js";
import { renderMarkdown } from "../src/ui/markdown.js";

describe("help content", () => {
  it("covers the core topics", () => {
    for (const heading of [
      "Your master password",
      "Your recovery words",
      "Fingerprint unlock",
      "Sign-in codes",
      "Password dates and change reminders",
      "Sync through your own cloud",
      "Backup packages",
      "Pairing a cloud or export target",
      "Agents",
      "Colours and skins",
    ]) {
      expect(HELP_MARKDOWN).toContain(heading);
    }
  });

  it("answers the questions that matter", () => {
    for (const question of [
      "I forgot my master password",
      "I lost my phone",
      "Does MyKey work without internet",
      "Can the company read my passwords",
      "How do I bring my passwords from Chrome or Firefox",
    ]) {
      expect(FAQ_MARKDOWN).toContain(question);
    }
  });

  it("never mentions the parked Private vault", () => {
    expect(HELP_MARKDOWN).not.toMatch(/private vault/i);
    expect(FAQ_MARKDOWN).not.toMatch(/private vault/i);
  });

  it("carries no web links in the body (offline rule)", () => {
    expect(HELP_MARKDOWN).not.toMatch(/https?:\/\//);
    expect(FAQ_MARKDOWN).not.toMatch(/https?:\/\//);
  });
});

describe("about info", () => {
  it("carries the seller, support, and attribution facts", () => {
    const info = aboutInfo();
    expect(info.vendor).toBe("2351485 ALBERTA INC.");
    expect(info.supportEmail).toBe("info@aimlds.org");
    expect(info.ownerUrl).toBe("https://nrupalakolkar.com");
    expect(info.builderUrl).toBe("https://muse.ai/join");
    expect(info.referralCode).toBe("101EEK");
    expect(info.referralLine).toContain("we both earn tokens");
    expect(info.licenceSummary).toContain("proprietary");
    expect(info.licenceSummary).toContain("Apache 2.0");
    expect(info.version).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

describe("markdown renderer", () => {
  it("renders headings, bullets, and bold as DOM", () => {
    const node = renderMarkdown(
      "# Title\n\n## Section\n\n- one\n- two **bold** words\n\nA paragraph.",
    );
    expect(node.querySelector("h3")?.textContent).toBe("Title");
    expect(node.querySelector("h4")?.textContent).toBe("Section");
    const items = node.querySelectorAll("li");
    expect(items).toHaveLength(2);
    expect(items[1]?.querySelector("strong")?.textContent).toBe("bold");
    expect(node.querySelector("p")?.textContent).toBe("A paragraph.");
  });

  it("strips the leading source comment", () => {
    const node = renderMarkdown(HELP_MARKDOWN);
    expect(node.textContent).not.toContain("Canonical in-app help");
    expect(node.querySelector("h3")?.textContent).toBe("How MyKey works");
  });

  it("treats markup in the text as text, never as HTML", () => {
    const node = renderMarkdown("Hello <script>alert(1)</script> world");
    expect(node.querySelector("script")).toBeNull();
    expect(node.textContent).toContain("<script>");
  });
});
