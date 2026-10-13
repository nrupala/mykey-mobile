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

/** Content-side logic. This file is injected on demand (activeTab +
 * scripting) into the TOP FRAME ONLY — never statically, never
 * into subframes. It does four things:
 *
 *  1. Classify forms: login vs payment vs password-change vs other.
 *     Payment forms are NEVER filled with logins and NEVER captured
 *     (card autofill is out of scope for v1; harvesting card fields
 *     as "logins" would be a leak, not a feature).
 *  2. Fill credentials the user explicitly asked for, into the two
 *     target fields of the page's login form — values are set via
 *     the native setter so frameworks notice, and nothing else on
 *     the page is touched.
 *  3. Watch (only when the user armed this tab from the popup) for
 *     a login form submission and report the candidate to the
 *     background. Nothing is saved at this point — the background
 *     asks the desktop, and the human clicks Save.
 *  4. Render the in-page save prompt inside a shadow root, showing
 *     the service and username — never the password.
 */

export type FormKind = "login" | "payment" | "change-password" | "other";

const CC_AUTOCOMPLETE = new Set([
  "cc-number",
  "cc-exp",
  "cc-exp-month",
  "cc-exp-year",
  "cc-csc",
  "cc-name",
  "cc-type",
  "cc-given-name",
  "cc-family-name",
]);
const CC_NAME_HINT = /(cc|card)[-_ ]?(num|number|csc|cvc|exp)/i;
const OTP_HINT = /(^|[-_ ])(otp|totp|mfa|2fa|one[-_ ]?time)([-_ ]|$)/i;

type Input = HTMLInputElement;

function isVisible(el: Input): boolean {
  const style = (el.ownerDocument?.defaultView ?? window).getComputedStyle(el);
  return style.display !== "none" && style.visibility !== "hidden"
    && el.type !== "hidden";
}

function inputsIn(root: ParentNode): Input[] {
  return Array.from(root.querySelectorAll("input")) as Input[];
}

export function isPaymentForm(form: HTMLFormElement): boolean {
  for (const input of inputsIn(form)) {
    const ac = (input.autocomplete || "").toLowerCase().split(" ");
    if (ac.some((token) => CC_AUTOCOMPLETE.has(token))) return true;
    const hint = `${input.name} ${input.id}`;
    if (CC_NAME_HINT.test(hint) && input.type !== "password") return true;
  }
  return false;
}

export function passwordInputs(form: HTMLFormElement): Input[] {
  return inputsIn(form).filter(
    (i) => i.type === "password" && !i.disabled,
  );
}

export function usernameInputFor(
  form: HTMLFormElement,
  passwordInput: Input,
): Input | null {
  const candidates = inputsIn(form).filter(
    (i) =>
      !i.disabled &&
      i !== passwordInput &&
      ["text", "email", "tel", ""].includes(i.type) &&
      isVisible(i),
  );
  const flagged = candidates.find((i) =>
    (i.autocomplete || "").toLowerCase().includes("username"),
  );
  if (flagged) return flagged;
  const email = candidates.find((i) => i.type === "email");
  if (email) return email;
  // The nearest visible text-ish input BEFORE the password field is
  // the conventional username slot.
  const formInputs = inputsIn(form);
  const pwIndex = formInputs.indexOf(passwordInput);
  const before = candidates.filter(
    (i) => formInputs.indexOf(i) < pwIndex,
  );
  return before[before.length - 1] ?? candidates[0] ?? null;
}

export function classifyForm(form: HTMLFormElement): FormKind {
  if (isPaymentForm(form)) return "payment";
  const passwords = passwordInputs(form);
  if (passwords.length === 0) return "other";
  if (passwords.length > 1) return "change-password";
  return "login";
}

export interface LoginForm {
  form: HTMLFormElement;
  kind: FormKind;
  username: Input | null;
  password: Input;
}

/** The page's primary login form, if any. For change-password
 * forms, the "current password" field (autocomplete-marked, else
 * the first) is the fill target and new-password fields are left
 * alone. */
export function findLoginForm(doc: Document): LoginForm | null {
  const forms = Array.from(doc.querySelectorAll("form"));
  for (const form of forms) {
    const kind = classifyForm(form);
    if (kind !== "login" && kind !== "change-password") continue;
    const passwords = passwordInputs(form).filter(isVisible);
    if (passwords.length === 0) continue;
    const target =
      passwords.find((i) =>
        (i.autocomplete || "").toLowerCase().includes("current-password"),
      ) ?? passwords[0];
    if (!target) continue;
    return {
      form,
      kind,
      username: usernameInputFor(form, target),
      password: target,
    };
  }
  return null;
}

function setValue(input: Input, value: string): void {
  const proto = Object.getPrototypeOf(input) as object;
  const descriptor = Object.getOwnPropertyDescriptor(proto, "value");
  if (descriptor?.set) {
    descriptor.set.call(input, value);
  } else {
    input.value = value;
  }
  // Events must come from the element's own window: a content
  // script's realm differs from the page's, and dispatchEvent
  // rejects foreign-realm events.
  const EventCtor =
    input.ownerDocument?.defaultView?.Event ?? Event;
  input.dispatchEvent(new EventCtor("input", { bubbles: true }));
  input.dispatchEvent(new EventCtor("change", { bubbles: true }));
}

export function fillCredentials(
  doc: Document,
  username: string,
  password: string,
): { username: boolean; password: boolean } {
  const login = findLoginForm(doc);
  if (!login) return { username: false, password: false };
  let filledUsername = false;
  if (login.username && username) {
    setValue(login.username, username);
    filledUsername = true;
  }
  setValue(login.password, password);
  return { username: filledUsername, password: true };
}

export function findOtpInputs(doc: Document): Input[] {
  const all = inputsIn(doc.body ?? doc).filter(
    (i) => !i.disabled && isVisible(i) && i.type !== "password",
  );
  // Segmented one-character boxes win over a lone one-time-code
  // flag: sites commonly mark only the FIRST box with
  // autocomplete="one-time-code", and dumping the whole code into
  // a 1-char box is the classic autofill failure here.
  const segmented = all.filter(
    (i) =>
      i.maxLength === 1 &&
      (i.inputMode === "numeric" ||
        i.type === "tel" ||
        (i.autocomplete || "").toLowerCase().includes("one-time-code") ||
        OTP_HINT.test(`${i.name} ${i.id} ${i.placeholder} ${i.className}`)),
  );
  if (segmented.length >= 4) return segmented;
  const flagged = all.filter((i) =>
    (i.autocomplete || "").toLowerCase().includes("one-time-code"),
  );
  if (flagged.length > 0) return flagged;
  return all.filter(
    (i) =>
      OTP_HINT.test(`${i.name} ${i.id} ${i.placeholder}`) ||
      ((i.inputMode === "numeric" || i.type === "tel") && i.maxLength === 6),
  );
}

export function fillTotp(doc: Document, code: string): boolean {
  const inputs = findOtpInputs(doc);
  if (inputs.length === 0) return false;
  const segmented = inputs.filter((i) => i.maxLength === 1);
  if (segmented.length >= 4 && code.length === segmented.length) {
    segmented.forEach((input, idx) => setValue(input, code[idx] ?? ""));
    return true;
  }
  const target = inputs.find((i) => i.maxLength !== 1) ?? inputs[0];
  if (!target) return false;
  setValue(target, code);
  return true;
}

// ---------------------------------------------------------------------------
// save capture (armed per tab by an explicit user action in the popup)
// ---------------------------------------------------------------------------

export interface CapturedLogin {
  origin: string;
  username: string;
  password: string;
}

const ARMED = Symbol.for("mykey.captureArmed");

export function isTopFrame(win: Window): boolean {
  return win.top === win.self;
}

/** Arm submit watching on this page. Idempotent. Returns false when
 * refused (not the top frame). The callback receives the candidate
 * the moment a LOGIN form is submitted; payment, change-password
 * and non-login forms never produce a candidate. */
export function armCapture(
  win: Window,
  send: (captured: CapturedLogin) => void,
): boolean {
  if (!isTopFrame(win)) return false;
  const flagged = win as unknown as Record<symbol, boolean>;
  if (flagged[ARMED]) return true;
  flagged[ARMED] = true;
  win.document.addEventListener(
    "submit",
    (event) => {
      const form = event.target as HTMLFormElement | null;
      if (!form || form.tagName !== "FORM") return;
      if (classifyForm(form) !== "login") return;
      const passwords = passwordInputs(form);
      const passwordInput = passwords[0];
      if (!passwordInput) return;
      const password = passwordInput.value;
      const usernameInput = usernameInputFor(form, passwordInput);
      const username = usernameInput?.value ?? "";
      if (!password) return;
      send({
        origin: win.location.origin,
        username,
        password,
      });
    },
    true,
  );
  return true;
}

// ---------------------------------------------------------------------------
// in-page save prompt (shadow DOM; shows service + username only)
// ---------------------------------------------------------------------------

export interface SavePromptSpec {
  mode: "new" | "update";
  service: string;
  username: string;
}

export function showSavePrompt(
  doc: Document,
  spec: SavePromptSpec,
  onChoice: (accepted: boolean) => void,
): void {
  dismissSavePrompt(doc);
  const host = doc.createElement("div");
  host.setAttribute("data-mykey-save-prompt", "1");
  const shadow = host.attachShadow({ mode: "closed" });
  const card = doc.createElement("div");
  card.setAttribute(
    "style",
    "position:fixed;top:16px;right:16px;z-index:2147483647;" +
      "background:#101418;color:#f2f5f7;padding:14px 16px;" +
      "border-radius:12px;font:14px/1.45 system-ui,sans-serif;" +
      "box-shadow:0 8px 30px rgba(0,0,0,.45);max-width:320px",
  );
  const text = doc.createElement("p");
  text.setAttribute("style", "margin:0 0 10px");
  text.textContent =
    spec.mode === "new"
      ? `Save this login for ${spec.service} to MyKey?`
      : `Update the saved MyKey password for ${spec.username} on ${spec.service}? The saved password is different.`;
  const save = doc.createElement("button");
  save.textContent = spec.mode === "new" ? "Save to MyKey" : "Update password";
  save.setAttribute(
    "style",
    "margin-right:8px;padding:6px 12px;border-radius:8px;border:0;" +
      "background:#2f7fd0;color:#fff;cursor:pointer",
  );
  const dismiss = doc.createElement("button");
  dismiss.textContent = "Not now";
  dismiss.setAttribute(
    "style",
    "padding:6px 12px;border-radius:8px;border:1px solid #5a6672;" +
      "background:transparent;color:#f2f5f7;cursor:pointer",
  );
  let settled = false;
  const settle = (accepted: boolean) => {
    if (settled) return;
    settled = true;
    host.remove();
    onChoice(accepted);
  };
  save.addEventListener("click", () => settle(true));
  dismiss.addEventListener("click", () => settle(false));
  card.append(text, save, dismiss);
  shadow.append(card);
  doc.documentElement.append(host);
  setTimeout(() => settle(false), 30000);
}

export function dismissSavePrompt(doc: Document): void {
  doc
    .querySelectorAll("[data-mykey-save-prompt]")
    .forEach((el) => el.remove());
}
