// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// Copyright (c) 2026 2351485 ALBERTA INC.
//
// Content-side form behaviour, incl. leak gate 7 (save-capture
// never fires on non-login forms; card fields are never harvested)
// and gate 3's page half (capture arms only in the top frame).

import { describe, expect, it, vi } from "vitest";
import {
  armCapture,
  classifyForm,
  fillCredentials,
  fillTotp,
  findLoginForm,
} from "../src/content.js";
import {
  CHANGE_PW_PAGE,
  LOGIN_PAGE,
  OTP_PAGE,
  PAYMENT_PAGE,
  installPage,
} from "./support/pages.js";

function formOf(html: string, url = "https://github.com/login") {
  const dom = installPage(html, url);
  return dom.window.document.querySelector("form") as HTMLFormElement;
}

describe("form classification", () => {
  it("recognizes a plain login form", () => {
    const form = formOf(LOGIN_PAGE);
    expect(classifyForm(form)).toBe("login");
    expect(findLoginForm(form.ownerDocument)?.form.id).toBe("login");
  });

  it("classifies a payment form as payment even with a password box", () => {
    const form = formOf(PAYMENT_PAGE, "https://shop.example/checkout");
    expect(classifyForm(form)).toBe("payment");
    expect(findLoginForm(form.ownerDocument)).toBeNull();
  });

  it("classifies multi-password forms as change-password", () => {
    const form = formOf(CHANGE_PW_PAGE, "https://github.com/settings");
    expect(classifyForm(form)).toBe("change-password");
  });
});

describe("fill", () => {
  it("fills only the two credential fields and fires input events", () => {
    const form = formOf(LOGIN_PAGE);
    const doc = form.ownerDocument;
    const events: string[] = [];
    doc
      .getElementById("u")
      ?.addEventListener("input", () => events.push("u"));
    const result = fillCredentials(doc, "octocat", "FIXTURE-PW-ALPHA-123");
    expect(result).toEqual({ username: true, password: true });
    expect((doc.getElementById("u") as HTMLInputElement).value).toBe("octocat");
    expect((doc.getElementById("p") as HTMLInputElement).value).toBe(
      "FIXTURE-PW-ALPHA-123",
    );
    expect(events).toContain("u");
  });

  it("never fills into a payment form", () => {
    const form = formOf(PAYMENT_PAGE, "https://shop.example/checkout");
    const result = fillCredentials(
      form.ownerDocument,
      "octocat",
      "FIXTURE-PW-ALPHA-123",
    );
    expect(result).toEqual({ username: false, password: false });
  });

  it("fills a one-time code across segmented boxes", () => {
    const dom = installPage(OTP_PAGE, "https://github.com/verify");
    expect(fillTotp(dom.window.document, "123456")).toBe(true);
    const values = [...dom.window.document.querySelectorAll(".code")].map(
      (el) => (el as HTMLInputElement).value,
    );
    expect(values).toEqual(["1", "2", "3", "4", "5", "6"]);
  });
});

describe("save capture (gate 7 + top-frame rule)", () => {
  function captureOn(html: string, url: string) {
    const dom = installPage(html, url);
    const onCapture = vi.fn();
    const armed = armCapture(dom.window as never, onCapture);
    return { dom, onCapture, armed };
  }

  function submit(dom: ReturnType<typeof installPage>) {
    const form = dom.window.document.querySelector("form");
    form?.dispatchEvent(
      new dom.window.Event("submit", { bubbles: true, cancelable: true }),
    );
  }

  it("reports a login submission exactly once, with origin bound", () => {
    const { dom, onCapture, armed } = captureOn(LOGIN_PAGE, "https://github.com/login");
    expect(armed).toBe(true);
    (dom.window.document.getElementById("u") as HTMLInputElement).value = "octocat";
    (dom.window.document.getElementById("p") as HTMLInputElement).value = "FIXTURE-PW-ALPHA-123";
    submit(dom);
    expect(onCapture).toHaveBeenCalledTimes(1);
    expect(onCapture.mock.calls[0]?.[0]).toEqual({
      origin: "https://github.com",
      username: "octocat",
      password: "FIXTURE-PW-ALPHA-123",
    });
  });

  it("never reports a payment submission", () => {
    const { dom, onCapture, armed } = captureOn(PAYMENT_PAGE, "https://shop.example/checkout");
    expect(armed).toBe(true);
    submit(dom);
    expect(onCapture).not.toHaveBeenCalled();
  });

  it("never reports a change-password submission in v1", () => {
    const { dom, onCapture } = captureOn(CHANGE_PW_PAGE, "https://github.com/settings");
    submit(dom);
    expect(onCapture).not.toHaveBeenCalled();
  });

  it("refuses to arm inside an iframe", () => {
    const dom = installPage(LOGIN_PAGE, "https://github.com/login");
    const iframe = dom.window.document.createElement("iframe");
    dom.window.document.body.append(iframe);
    const child = iframe.contentWindow;
    expect(child).not.toBeNull();
    const onCapture = vi.fn();
    expect(armCapture(child as never, onCapture)).toBe(false);
  });
});
