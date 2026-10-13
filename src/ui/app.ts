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

/** The whole user interface: plain DOM, no framework. Design
 * rules (the product's simplicity doctrine): one obvious next
 * action per screen, plain words, big touch targets, every secret
 * rendered through textContent (never innerHTML), full keyboard
 * and screen-reader semantics. */

import { BRAND, DEVICE_SLOT_ID, VAULT_FILENAME } from "../brand.js";
import {
  BackupRefusedError,
  importPackageWithRecovery,
  inspectPackage,
} from "../vault/backup.js";
import {
  b64decode,
  b64encode,
  randomBytes,
  utf8Decode,
  utf8Encode,
} from "../vault/encoding.js";
import {
  classifyImport,
  exportCsv,
  EXPORT_FILENAME,
  genericMapEntries,
  parseImportCsv,
  rowsFromCsv,
  type ConflictPolicy,
  type GenericMapping,
  type ImportRecord,
} from "../vault/csvio.js";
import {
  rotationDueCount,
  rotationLine,
  rotationReport,
  rotationStatus,
} from "../vault/rotation.js";
import { store, type AppSettings } from "../vault/store.js";
import { chooseTheme, currentThemeChoice } from "./appearance.js";
import {
  CHAKRA_SPECTRUM,
  DEVICE_DARK,
  DEVICE_LIGHT,
  THEMES,
  THEME_ORDER,
} from "./themes.js";
import { totpNow, totpSecondsRemaining } from "../vault/totp.js";
import {
  VaultSession,
  WrongPasswordError,
  generatePassword,
  type VaultEntry,
} from "../vault/vault.js";
import {
  biometricAvailable,
  fetchDeviceWrapKey,
  isNativeApp,
  removeDeviceWrapKey,
  storeDeviceWrapKey,
} from "../platform/biometric.js";
import {
  chooseSyncFolder,
  exportFile,
  pickFile,
  syncFolderPull,
  syncFolderPush,
  syncFolderSupported,
} from "../platform/filesync.js";

// ------------------------------------------------------------------
// Tiny DOM helpers
// ------------------------------------------------------------------

type Child = Node | string | null | undefined | false;

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("aria-") || k === "role" || k === "id" || k === "type" ||
             k === "name" || k === "value" || k === "autocomplete" || k === "inputmode" ||
             k === "placeholder" || k === "for" || k === "href") {
      node.setAttribute(k, v);
    } else node.setAttribute(k, v);
  }
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function button(
  label: string,
  onClick: (ev: Event) => void | Promise<void>,
  variant: "primary" | "plain" | "danger" = "plain",
): HTMLButtonElement {
  const b = el("button", { type: "button", class: `btn btn-${variant}` }, label);
  b.addEventListener("click", (ev) => {
    void Promise.resolve(onClick(ev)).catch(showFatal);
  });
  return b;
}

function field(
  labelText: string,
  input: HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement,
  hint?: string,
): HTMLElement {
  const id = `f-${Math.random().toString(36).slice(2, 9)}`;
  input.id = id;
  const wrap = el("div", { class: "field" });
  const lab = el("label", { for: id }, labelText);
  wrap.append(lab, input);
  if (hint) wrap.append(el("p", { class: "hint", id: `${id}-hint` }, hint));
  return wrap;
}

function input(attrs: Record<string, string> = {}): HTMLInputElement {
  return el("input", { class: "text-input", ...attrs });
}

function showFatal(err: unknown): void {
  console.error(err);
  const main = document.querySelector("main")!;
  const alert = el(
    "div",
    { class: "alert alert-error", role: "alert" },
    err instanceof Error ? err.message : "Something went wrong.",
  );
  main.prepend(alert);
  alert.scrollIntoView();
}

function errorText(err: unknown): string {
  if (err instanceof WrongPasswordError) return err.message;
  if (err instanceof BackupRefusedError) return err.message;
  if (err instanceof Error) return err.message;
  return "Something went wrong. Please try again.";
}

// ------------------------------------------------------------------
// App state
// ------------------------------------------------------------------

interface AppState {
  settings: AppSettings;
  storedBytes: Uint8Array | null;
  session: VaultSession | null;
  syncHandle: FileSystemDirectoryHandle | null;
  autoLockTimer: number | null;
  totpTimer: number | null;
  clipTimer: number | null;
}

const state: AppState = {
  settings: null as unknown as AppSettings,
  storedBytes: null,
  session: null,
  syncHandle: null,
  autoLockTimer: null,
  totpTimer: null,
  clipTimer: null,
};

const main = () => document.querySelector("main")!;

function render(node: HTMLElement): void {
  stopTimers();
  const m = main();
  m.replaceChildren(node);
  const heading = m.querySelector("h2");
  if (heading) {
    heading.setAttribute("tabindex", "-1");
    (heading as HTMLElement).focus({ preventScroll: true });
  }
  window.scrollTo(0, 0);
}

function stopTimers(): void {
  if (state.autoLockTimer !== null) window.clearTimeout(state.autoLockTimer);
  if (state.totpTimer !== null) window.clearInterval(state.totpTimer);
  state.autoLockTimer = null;
  state.totpTimer = null;
}

// ------------------------------------------------------------------
// Persistence + locking
// ------------------------------------------------------------------

async function persist(): Promise<void> {
  if (!state.session) return;
  const bytes = await state.session.serialize();
  state.storedBytes = bytes;
  await store.setVaultBytes(bytes);
  if (state.syncHandle) {
    await syncFolderPush(state.syncHandle, bytes).catch(() => false);
  }
}

function armAutoLock(): void {
  if (state.autoLockTimer !== null) window.clearTimeout(state.autoLockTimer);
  state.autoLockTimer = null;
  const minutes = state.settings.autoLockMinutes;
  if (minutes > 0 && state.session) {
    state.autoLockTimer = window.setTimeout(() => {
      lock("Your vault locked itself after a quiet spell.");
    }, minutes * 60_000);
  }
}

function lock(notice?: string): void {
  state.session?.lock();
  state.session = null;
  stopTimers();
  void renderLocked(notice);
}

async function copySecret(value: string, what: string, status: HTMLElement): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    status.textContent = `Copy failed — your browser blocked it. You can reveal and copy by hand.`;
    return;
  }
  status.textContent = `${what} copied. It will be cleared from the clipboard shortly.`;
  if (state.clipTimer !== null) window.clearTimeout(state.clipTimer);
  const seconds = Math.max(5, state.settings.clipboardClearSeconds);
  state.clipTimer = window.setTimeout(async () => {
    try {
      const current = await navigator.clipboard.readText();
      if (current === value) await navigator.clipboard.writeText("");
    } catch {
      /* clipboard no longer ours or unreadable — leave it */
    }
  }, seconds * 1000);
}

// ------------------------------------------------------------------
// Locked screens
// ------------------------------------------------------------------

async function renderLocked(notice?: string): Promise<void> {
  const root = el("section", { class: "screen" });
  if (notice) root.append(el("p", { class: "alert alert-info", role: "status" }, notice));
  root.append(el("h2", {}, state.storedBytes ? "Your vault is locked" : "Welcome to MyKey"));
  root.append(
    el(
      "p",
      { class: "lede" },
      state.storedBytes
        ? "Enter your master password to open your vault. Your passwords never leave this device."
        : "MyKey keeps your passwords in one encrypted file that only you can open. Nothing is sent anywhere — there is no account and no server.",
    ),
  );

  if (state.storedBytes) {
    root.append(await unlockForm());
  } else {
    const actions = el("div", { class: "action-stack" });
    actions.append(
      button("Create a new vault", () => renderCreate(), "primary"),
      button("Open a vault file", () => renderOpenFile()),
      button("Restore from a backup package", () => renderRestore()),
    );
    root.append(actions);
  }
  render(root);
}

async function unlockForm(): Promise<HTMLElement> {
  const box = el("div", { class: "card" });
  const error = el("p", { class: "alert alert-error hidden", role: "alert" });
  const status = el("p", { class: "status", "aria-live": "polite" });

  // Fingerprint / biometric unlock (Android app, opt-in).
  if (isNativeApp() && state.settings.deviceSlotEnabled && (await biometricAvailable())) {
    box.append(
      button("Unlock with fingerprint", async () => {
        const keyB64 = await fetchDeviceWrapKey();
        if (!keyB64) {
          error.textContent = "Fingerprint unlock didn't work. Use your master password.";
          error.classList.remove("hidden");
          return;
        }
        try {
          const session = await VaultSession.openWithWrapKey(
            state.storedBytes!,
            DEVICE_SLOT_ID,
            b64decode(keyB64),
          );
          await enterVault(session);
        } catch {
          error.textContent =
            "Fingerprint unlock no longer matches this vault. Use your master password.";
          error.classList.remove("hidden");
        }
      }, "primary"),
    );
    box.append(el("p", { class: "or" }, "or"));
  }

  const password = input({ type: "password", autocomplete: "current-password" });
  const phrase = el("textarea", {
    class: "text-input",
    rows: "3",
    autocomplete: "off",
    "aria-label": "Recovery phrase (12 words)",
  }) as HTMLTextAreaElement;
  let mode: "password" | "phrase" = "password";

  const form = el("form", { class: "form" });
  const pwField = field("Master password", password);
  const phraseField = field(
    "Recovery phrase",
    phrase,
    "The 12 words you saved when you set up recovery.",
  );
  phraseField.classList.add("hidden");
  form.append(pwField, phraseField, error);
  const submit = button(mode === "password" ? "Unlock" : "Unlock with phrase", async () => {}, "primary");
  submit.type = "submit";
  form.append(submit);

  const toggle = button("Use my recovery phrase instead", () => {
    mode = mode === "password" ? "phrase" : "password";
    pwField.classList.toggle("hidden", mode !== "password");
    phraseField.classList.toggle("hidden", mode !== "phrase");
    submit.textContent = mode === "password" ? "Unlock" : "Unlock with phrase";
    toggle.textContent =
      mode === "password" ? "Use my recovery phrase instead" : "Use my master password instead";
  });

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    error.classList.add("hidden");
    status.textContent = "Unlocking… this can take a few seconds.";
    try {
      const session =
        mode === "password"
          ? await VaultSession.openWithPassword(state.storedBytes!, password.value)
          : await VaultSession.openWithPhrase(state.storedBytes!, phrase.value);
      password.value = "";
      phrase.value = "";
      await enterVault(session);
    } catch (err) {
      status.textContent = "";
      error.textContent =
        err instanceof WrongPasswordError
          ? mode === "password"
            ? "That password doesn't match this vault. Please try again."
            : "That recovery phrase doesn't match this vault. Check the words and try again."
          : errorText(err);
      error.classList.remove("hidden");
    }
  });

  box.append(form, toggle, status);

  const other = el("div", { class: "action-stack" });
  other.append(
    button("Open a different vault file", () => renderOpenFile()),
    button("Restore from a backup package", () => renderRestore()),
    button("Remove this vault from this device", async () => {
      if (!window.confirm(
        "Remove the vault copy from this device? Your vault file and any backup packages stay safe wherever you saved them. You will need the file again to open it here.",
      )) return;
      await store.clearVault();
      await store.clearLastBackupAt();
      state.storedBytes = null;
      if (state.settings.deviceSlotEnabled) {
        await removeDeviceWrapKey();
        state.settings = { ...state.settings, deviceSlotEnabled: false };
        await store.setSettings(state.settings);
      }
      void renderLocked("The vault copy was removed from this device.");
    }, "danger"),
  );
  box.append(other);
  return box;
}

function renderCreate(): void {
  const root = el("section", { class: "screen" });
  root.append(el("h2", {}, "Create your vault"));
  root.append(
    el("p", { class: "lede" },
      "Choose a master password you can remember. It is the only key to your vault — nobody can reset it for you, not even us."),
  );
  const error = el("p", { class: "alert alert-error hidden", role: "alert" });
  const pw = input({ type: "password", autocomplete: "new-password" });
  const pw2 = input({ type: "password", autocomplete: "new-password" });
  const form = el("form", { class: "form" });
  form.append(
    field("Master password (at least 12 characters)", pw),
    field("Type it again", pw2),
    error,
  );
  const submit = button("Create vault", async () => {}, "primary");
  submit.type = "submit";
  form.append(submit, button("Back", () => void renderLocked()));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    error.classList.add("hidden");
    if (pw.value.length < 12) {
      error.textContent = "Please use at least 12 characters.";
      error.classList.remove("hidden");
      return;
    }
    if (pw.value !== pw2.value) {
      error.textContent = "The two passwords don't match.";
      error.classList.remove("hidden");
      return;
    }
    try {
      const session = await VaultSession.createNew(pw.value);
      state.session = session;
      pw.value = "";
      pw2.value = "";
      renderPhraseSetup(session, true);
    } catch (err) {
      error.textContent = errorText(err);
      error.classList.remove("hidden");
    }
  });
  root.append(form);
  render(root);
}

function renderPhraseSetup(session: VaultSession, firstTime: boolean): void {
  const root = el("section", { class: "screen" });
  root.append(el("h2", {}, "Save your recovery phrase"));
  root.append(
    el("p", { class: "lede" },
      "These 12 words are the only way back into your vault if you forget your master password. Write them on paper and keep the paper somewhere safe. Anyone with these words can open your vault."),
  );
  const grid = el("ol", { class: "phrase-grid" });
  const done = button(firstTime ? "I've saved my phrase — open my vault" : "Done", async () => {
    await persist();
    renderUnlocked();
  }, "primary");
  done.disabled = true;
  const confirmBox = el("input", { type: "checkbox" }) as HTMLInputElement;
  confirmBox.addEventListener("change", () => {
    done.disabled = !confirmBox.checked;
  });
  const confirmLabel = el(
    "label",
    { class: "checkbox" },
    confirmBox,
    " I wrote these words down and stored them safely.",
  );
  root.append(grid, confirmLabel, done);
  render(root);
  void session.setupRecovery().then((phrase) => {
    for (const word of phrase.split(" ")) {
      grid.append(el("li", {}, word));
    }
    void persist();
  });
}

function renderOpenFile(): void {
  const root = el("section", { class: "screen" });
  root.append(el("h2", {}, "Open a vault file"));
  root.append(
    el("p", { class: "lede" },
      "Pick your vault file (it ends in .mykey). A copy is kept on this device so you can open it again without the file."),
  );
  const error = el("p", { class: "alert alert-error hidden", role: "alert" });
  let bytes: Uint8Array | null = null;
  const fileName = el("p", { class: "status", "aria-live": "polite" });
  const pw = input({ type: "password", autocomplete: "current-password" });
  const form = el("form", { class: "form" });
  form.append(
    button("Choose vault file", async () => {
      const picked = await pickFile();
      if (picked) {
        bytes = picked.bytes;
        fileName.textContent = `Selected: ${picked.name}`;
      }
    }),
    fileName,
    field("Master password", pw),
    error,
  );
  const submit = button("Open this vault", async () => {}, "primary");
  submit.type = "submit";
  form.append(submit, button("Back", () => void renderLocked()));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    error.classList.add("hidden");
    if (!bytes) {
      error.textContent = "Choose your vault file first.";
      error.classList.remove("hidden");
      return;
    }
    try {
      const session = await VaultSession.openWithPassword(bytes, pw.value);
      if (state.storedBytes && session.vaultId !== storedVaultId()) {
        if (!window.confirm(
          "This is a different vault from the one on this device. Replace the device copy? The other vault stays safe in its own file.",
        )) return;
      }
      state.storedBytes = bytes;
      await store.setVaultBytes(bytes);
      pw.value = "";
      await enterVault(session);
    } catch (err) {
      error.textContent =
        err instanceof WrongPasswordError
          ? "That password doesn't match this vault file."
          : errorText(err);
      error.classList.remove("hidden");
    }
  });
  root.append(form);
  render(root);
}

function vaultIdOf(bytes: Uint8Array | null): string | null {
  if (!bytes) return null;
  try {
    return JSON.parse(new TextDecoder().decode(bytes)).vault_id ?? null;
  } catch {
    return null;
  }
}

function storedVaultId(): string | null {
  return vaultIdOf(state.storedBytes);
}

function renderRestore(): void {
  const root = el("section", { class: "screen" });
  root.append(el("h2", {}, "Restore from a backup package"));
  root.append(
    el("p", { class: "lede" },
      "A backup package (ends in .mykeybak) restores your vault using your recovery phrase. For your protection, also type the source fingerprint you recorded when the backup was made — a package cannot vouch for itself."),
  );
  const error = el("p", { class: "alert alert-error hidden", role: "alert" });
  const status = el("p", { class: "status", "aria-live": "polite" });
  let pkgBytes: Uint8Array | null = null;
  const info = el("div", { class: "card hidden" });
  const phrase = el("textarea", {
    class: "text-input", rows: "3", autocomplete: "off",
    "aria-label": "Recovery phrase (12 words)",
  }) as HTMLTextAreaElement;
  const fingerprint = input({ autocomplete: "off", placeholder: "e.g. 48aa:1618:ba56:…" });
  const pw = input({ type: "password", autocomplete: "current-password" });

  const form = el("form", { class: "form" });
  form.append(
    button("Choose backup package", async () => {
      const picked = await pickFile();
      if (!picked) return;
      error.classList.add("hidden");
      try {
        const meta = inspectPackage(picked.bytes);
        pkgBytes = picked.bytes;
        info.replaceChildren(
          el("p", {}, `From device: ${meta.sourceDeviceId}`),
          el("p", {}, `Package fingerprint: ${meta.sourceFingerprint}`),
          el("p", {}, meta.signatureValid
            ? "Package signature: valid"
            : "Package signature: INVALID — do not trust this package."),
        );
        info.classList.remove("hidden");
      } catch (err) {
        error.textContent = errorText(err);
        error.classList.remove("hidden");
      }
    }),
    info,
    field("Your recovery phrase", phrase),
    field("Source fingerprint (from when the backup was made)", fingerprint),
    field("Master password for the restored vault", pw),
    error,
    status,
  );
  const submit = button("Restore my vault", async () => {}, "primary");
  submit.type = "submit";
  form.append(submit, button("Back", () => void renderLocked()));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    error.classList.add("hidden");
    if (!pkgBytes) {
      error.textContent = "Choose your backup package first.";
      error.classList.remove("hidden");
      return;
    }
    try {
      const lastSeen = await store.getLastBackupAt();
      const result = await importPackageWithRecovery(pkgBytes, phrase.value, fingerprint.value);
      const meta = inspectPackage(pkgBytes);
      if (lastSeen !== undefined && meta.createdAt < lastSeen) {
        if (!window.confirm(
          "This backup is older than one you already restored on this device. Restore it anyway? Anything added since then won't be in it.",
        )) return;
      }
      const session = await VaultSession.openWithPassword(result.vaultBytes, pw.value);
      state.storedBytes = result.vaultBytes;
      await store.setVaultBytes(result.vaultBytes);
      await store.setLastBackupAt(meta.createdAt);
      phrase.value = "";
      pw.value = "";
      await enterVault(session);
    } catch (err) {
      error.textContent = errorText(err);
      error.classList.remove("hidden");
    }
  });
  root.append(form);
  render(root);
}

// ------------------------------------------------------------------
// Unlocked screens
// ------------------------------------------------------------------

async function enterVault(session: VaultSession): Promise<void> {
  state.session = session;
  if (session.needsPersist()) await persist();
  renderUnlocked();
}

function renderUnlocked(selectedId?: string): void {
  const session = state.session!;
  const root = el("section", { class: "screen" });
  root.append(el("h2", {}, "Your passwords"));
  const defaultRotateDays = session.vaultSettings().default_rotate_days;

  const dueCount = rotationDueCount(session.listEntries(), defaultRotateDays);
  if (dueCount > 0) {
    root.append(
      el("p", { class: "alert alert-info", role: "note" },
        `${dueCount} password${dueCount === 1 ? " is" : "s are"} due for a change — see Password rotation below.`),
    );
  }

  if (session.auditSealed) {
    root.append(
      el("p", { class: "alert alert-info", role: "note" },
        "This vault was sealed by the desktop app's audit log. The app can't check that log here, so it can't confirm nothing was rolled back. Your passwords themselves are fully verified."),
    );
  }

  const toolbar = el("div", { class: "toolbar" });
  const search = input({ type: "search", placeholder: "Search service, name, or tag", "aria-label": "Search your passwords" });
  toolbar.append(search, button("Lock now", () => lock()));
  root.append(toolbar);

  const listRegion = el("div", { class: "entry-list" });
  root.append(listRegion);

  const detail = el("div", { class: "detail" });
  root.append(detail);

  root.append(
    button("Add a password", () => renderEditor(null, selectedId), "primary"),
  );
  root.append(rotationPanel());
  root.append(settingsPanel());

  const drawList = () => {
    listRegion.replaceChildren();
    const entries = session.searchEntries(search.value.trim());
    if (entries.length === 0) {
      listRegion.append(
        el("p", { class: "status" },
          search.value.trim() ? "Nothing matches that search." : "No passwords yet. Add your first one below."),
      );
    }
    const sorted = [...entries].sort((a, b) =>
      a.favourite === b.favourite
        ? a.service.localeCompare(b.service)
        : a.favourite ? -1 : 1,
    );
    for (const entry of sorted) {
      const item = el("button", {
        type: "button",
        class: `entry-item${entry.id === selectedId ? " selected" : ""}`,
        "aria-current": entry.id === selectedId ? "true" : "false",
      });
      item.append(
        el("span", { class: "entry-service" }, (entry.favourite ? "★ " : "") + entry.service),
        el("span", { class: "entry-user" }, entry.username),
      );
      if (entry.totp_secret) {
        const code = el("span", { class: "entry-totp", "data-totp-for": entry.id }, "······");
        item.append(code);
      }
      const rState = rotationStatus(entry, defaultRotateDays).state;
      if (rState === "overdue" || rState === "due_soon") {
        item.append(el("span", { class: "entry-rotation" },
          rState === "overdue" ? "⚠️ change overdue" : "⏰ change due"));
      }
      item.addEventListener("click", () => {
        renderUnlocked(entry.id);
      });
      listRegion.append(item);
    }
  };

  search.addEventListener("input", drawList);
  drawList();

  if (selectedId) {
    try {
      detail.append(entryDetail(session.getEntry(selectedId)));
    } catch {
      /* entry was deleted */
    }
  }

  render(root);
  armAutoLock();

  // Live TOTP codes.
  const tick = async () => {
    if (!state.session) return;
    for (const node of document.querySelectorAll<HTMLElement>("[data-totp-for]")) {
      const entry = session.listEntries().find((e) => e.id === node.dataset.totpFor);
      if (entry?.totp_secret) {
        node.textContent = `Code: ${await totpNow(entry.totp_secret)} (${totpSecondsRemaining()}s)`;
      }
    }
  };
  void tick();
  state.totpTimer = window.setInterval(() => void tick(), 1000);
}

/** The calm Rotation section of the unlocked screen: only what
 * needs attention (due soon, overdue, date not recorded), each
 * with its plain-language line. No nagging anywhere else. */
function rotationPanel(): HTMLElement {
  const session = state.session!;
  const panel = el("section", { class: "card rotation", "aria-label": "Password rotation" });
  panel.append(el("h3", {}, "Password rotation"));
  const defaultDays = session.vaultSettings().default_rotate_days;
  const rows = rotationReport(session.listEntries(), defaultDays)
    .filter((r) => r.state === "overdue" || r.state === "due_soon" || r.state === "unknown");
  if (rows.length === 0) {
    panel.append(el("p", { class: "status" }, "Nothing needs changing right now."));
    return panel;
  }
  for (const r of rows) {
    const line = rotationLine(
      { password_set_at: r.password_set_at, rotate_days: r.rotate_days }, null);
    const suffix = r.state === "overdue" ? " — overdue"
      : r.state === "due_soon" ? " — due soon" : "";
    const item = el("button", { type: "button", class: "entry-item" });
    item.append(
      el("span", { class: "entry-service" }, r.service),
      el("span", { class: "entry-user" }, `${line}${suffix}`),
    );
    item.addEventListener("click", () => renderUnlocked(r.id));
    panel.append(item);
  }
  return panel;
}

function entryDetail(entry: VaultEntry): HTMLElement {
  const session = state.session!;
  const box = el("article", { class: "card", "aria-label": `${entry.service} details` });
  box.append(el("h3", {}, (entry.favourite ? "★ " : "") + entry.service));
  const status = el("p", { class: "status", "aria-live": "polite" });

  const showRow = (labelText: string, value: string, copyLabel?: string) => {
    const row = el("div", { class: "kv" });
    row.append(el("span", { class: "kv-label" }, labelText), el("span", { class: "kv-value" }, value));
    if (copyLabel) {
      row.append(button(copyLabel, () => copySecret(value, labelText, status)));
    }
    box.append(row);
  };

  showRow("Username", entry.username || "—", entry.username ? "Copy" : undefined);
  const pwRow = el("div", { class: "kv" });
  const pwValue = el("span", { class: "kv-value" }, "••••••••");
  let shown = false;
  const showBtn = button("Show", () => {
    shown = !shown;
    pwValue.textContent = shown ? entry.password : "••••••••";
    showBtn.textContent = shown ? "Hide" : "Show";
  });
  pwRow.append(el("span", { class: "kv-label" }, "Password"), pwValue, showBtn,
    button("Copy", () => copySecret(entry.password, "Password", status)));
  box.append(pwRow);

  if (entry.totp_secret) {
    const totpRow = el("div", { class: "kv" });
    const totpValue = el("span", { class: "kv-value code", "data-totp-for": entry.id }, "······");
    totpRow.append(el("span", { class: "kv-label" }, "Sign-in code"), totpValue,
      button("Copy", async () => {
        await copySecret(await totpNow(entry.totp_secret), "Sign-in code", status);
      }));
    box.append(totpRow);
  }
  if (entry.url) showRow("Website", entry.url);
  if (entry.notes) showRow("Notes", entry.notes);
  if (entry.tags.length) showRow("Tags", entry.tags.join(", "));
  showRow("Password age",
    rotationLine(entry, session.vaultSettings().default_rotate_days));

  const actions = el("div", { class: "action-row" });
  actions.append(
    button("Edit", () => renderEditor(entry, entry.id)),
    button("Mark as changed today", async () => {
      await session.markPasswordChanged(entry.id);
      await persist();
      renderUnlocked(entry.id);
    }),
    button("Delete", async (ev) => {
      const btn = ev.currentTarget as HTMLButtonElement;
      if (btn.dataset.armed !== "1") {
        btn.dataset.armed = "1";
        btn.textContent = "Tap again to delete for good";
        return;
      }
      await session.deleteEntry(entry.id);
      await persist();
      renderUnlocked();
    }, "danger"),
  );
  box.append(actions, status);
  return box;
}

/** Strength estimate for the editor's meter: length and variety,
 * shown as five segments plus a word — never colour alone. */
function passwordStrength(pw: string): { score: number; word: string } {
  if (!pw) return { score: 0, word: "" };
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (pw.length >= 16) score++;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/]
    .filter((r) => r.test(pw)).length;
  if (classes >= 3) score++;
  if (classes === 4 && pw.length >= 12) score++;
  const words = ["", "Very weak", "Weak", "Fair", "Strong", "Excellent"];
  return { score: Math.min(5, score), word: words[Math.min(5, score)]! };
}

function strengthMeter(): {
  root: HTMLElement;
  update: (pw: string) => void;
} {
  const segs: HTMLElement[] = [];
  const bar = el("div", { class: "meter", "aria-hidden": "true" });
  for (let i = 0; i < 5; i++) {
    const seg = el("span", { class: "meter-seg" });
    segs.push(seg);
    bar.append(seg);
  }
  const word = el("p", { class: "meter-word", "aria-live": "polite" });
  const root = el("div", {}, bar, word);
  return {
    root,
    update(pw: string) {
      const { score, word: label } = passwordStrength(pw);
      segs.forEach((seg, i) => {
        seg.classList.toggle("on", i < score);
        seg.dataset.level = String(Math.max(1, score));
      });
      word.textContent = pw ? `Password strength: ${label}` : "";
    },
  };
}

function renderEditor(entry: VaultEntry | null, backTo?: string): void {
  const session = state.session!;
  const root = el("section", { class: "screen" });
  root.append(el("h2", {}, entry ? `Edit ${entry.service}` : "Add a password"));
  const error = el("p", { class: "alert alert-error hidden", role: "alert" });
  const f = {
    service: input({ autocomplete: "off", value: entry?.service ?? "" }),
    username: input({ autocomplete: "off", value: entry?.username ?? "" }),
    password: input({ type: "text", autocomplete: "off", value: entry?.password ?? "" }),
    url: input({ inputmode: "url", autocomplete: "off", value: entry?.url ?? "" }),
    totp: input({ autocomplete: "off", value: entry?.totp_secret ?? "" }),
    tags: input({ autocomplete: "off", value: entry?.tags.join(", ") ?? "" }),
  };
  const notes = el("textarea", { class: "text-input", rows: "3" }) as HTMLTextAreaElement;
  notes.value = entry?.notes ?? "";
  const favourite = el("input", { type: "checkbox" }) as HTMLInputElement;
  favourite.checked = entry?.favourite ?? false;

  const meter = strengthMeter();
  f.password.addEventListener("input", () => meter.update(f.password.value));
  meter.update(f.password.value);

  // Per-entry rotation override: vault default, never, a preset
  // period, or a custom number of days.
  const rotateSelect = el("select", { class: "text-input" }) as HTMLSelectElement;
  const ROTATE_PRESETS = ["30", "90", "180", "365"];
  for (const [label, value] of [
    ["Use the vault default", "default"],
    ["Never — don't remind me about this one", "never"],
    ...ROTATE_PRESETS.map((d) => [`Every ${d} days`, d] as [string, string]),
    ["Custom…", "custom"],
  ] as [string, string][]) {
    rotateSelect.append(el("option", { value }, label));
  }
  const rotateCustom = input({ type: "number", min: "1", max: "36500", inputmode: "numeric" });
  const currentRotate = entry?.rotate_days ?? null;
  if (currentRotate === null) rotateSelect.value = "default";
  else if (currentRotate === 0) rotateSelect.value = "never";
  else if (ROTATE_PRESETS.includes(String(currentRotate))) {
    rotateSelect.value = String(currentRotate);
  } else {
    rotateSelect.value = "custom";
    rotateCustom.value = String(currentRotate);
  }
  const rotateCustomField = field("Custom period (days)", rotateCustom);
  const syncRotateCustom = () => {
    rotateCustomField.classList.toggle("hidden", rotateSelect.value !== "custom");
  };
  rotateSelect.addEventListener("change", syncRotateCustom);
  syncRotateCustom();
  const readRotateDays = (): number | null => {
    if (rotateSelect.value === "default") return null;
    if (rotateSelect.value === "never") return 0;
    if (rotateSelect.value === "custom") {
      const days = Number(rotateCustom.value);
      if (!Number.isInteger(days) || days < 1) {
        throw new Error("Type a whole number of days (1 or more), or pick another choice.");
      }
      return days;
    }
    return Number(rotateSelect.value);
  };

  const form = el("form", { class: "form" });
  form.append(
    field("Service or app name", f.service),
    field("Username or email", f.username),
    field("Password", f.password),
    meter.root,
    button("Make a strong password for me", () => {
      f.password.value = generatePassword(20);
      f.password.type = "text";
      meter.update(f.password.value);
    }),
    field("Website (optional)", f.url),
    field("Notes (optional)", notes),
    field("Sign-in code secret (optional)", f.totp,
      "The setup key from the service, if it uses one-time sign-in codes."),
    field("Tags (optional, separated by commas)", f.tags),
    el("label", { class: "checkbox" }, favourite, " Favourite"),
    field("Remind me to change this password", rotateSelect,
      "MyKey notes the day each password was set and works out the change date from this."),
    rotateCustomField,
    error,
  );
  const submit = button(entry ? "Save changes" : "Save password", async () => {}, "primary");
  submit.type = "submit";
  form.append(submit, button("Cancel", () => renderUnlocked(backTo)));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    error.classList.add("hidden");
    const values = {
      service: f.service.value.trim(),
      username: f.username.value,
      password: f.password.value,
      url: f.url.value.trim(),
      notes: notes.value,
      totp_secret: f.totp.value.trim(),
      tags: f.tags.value.split(",").map((t) => t.trim()).filter(Boolean),
      favourite: favourite.checked,
      rotate_days: null as number | null,
    };
    try {
      values.rotate_days = readRotateDays();
    } catch (err) {
      error.textContent = errorText(err);
      error.classList.remove("hidden");
      return;
    }
    try {
      const saved = entry
        ? await session.updateEntry(entry.id, values)
        : await session.addEntry(values);
      await persist();
      renderUnlocked(saved.id);
    } catch (err) {
      error.textContent = errorText(err);
      error.classList.remove("hidden");
    }
  });
  root.append(form);
  render(root);
  armAutoLock();
}

// ------------------------------------------------------------------
// Settings
// ------------------------------------------------------------------

function settingsPanel(): HTMLElement {
  const session = state.session!;
  const panel = el("section", { class: "card settings", "aria-label": "Settings" });
  panel.append(el("h3", {}, "Settings"));
  const status = el("p", { class: "status", "aria-live": "polite" });

  // Auto-lock
  const lockSelect = el("select", { class: "text-input" }) as HTMLSelectElement;
  for (const [label, value] of [
    ["After 1 minute", "1"], ["After 5 minutes", "5"],
    ["After 15 minutes", "15"], ["Never (not recommended)", "0"],
  ] as const) {
    const opt = el("option", { value }, label);
    if (Number(value) === state.settings.autoLockMinutes) opt.selected = true;
    lockSelect.append(opt);
  }
  lockSelect.addEventListener("change", async () => {
    state.settings = { ...state.settings, autoLockMinutes: Number(lockSelect.value) };
    await store.setSettings(state.settings);
    armAutoLock();
    status.textContent = "Auto-lock setting saved.";
  });
  panel.append(field("Lock the vault when it's been quiet", lockSelect));

  const hideBox = el("input", { type: "checkbox" }) as HTMLInputElement;
  hideBox.checked = state.settings.lockOnHide;
  hideBox.addEventListener("change", async () => {
    state.settings = { ...state.settings, lockOnHide: hideBox.checked };
    await store.setSettings(state.settings);
  });
  panel.append(el("label", { class: "checkbox" }, hideBox,
    " Lock when the app is hidden or the screen turns off"));

  // Vault-wide password rotation default (stored in the encrypted
  // vault itself, so every client agrees). Per-entry choices win.
  const vaultDefault = session.vaultSettings().default_rotate_days;
  const rotateDefaultSelect = el("select", { class: "text-input" }) as HTMLSelectElement;
  const ROTATE_DEFAULT_PRESETS = ["30", "90", "180", "365"];
  for (const [label, value] of [
    ["No rotation by default", "never"],
    ...ROTATE_DEFAULT_PRESETS.map((d) => [`Change every ${d} days`, d] as [string, string]),
    ["Custom…", "custom"],
  ] as [string, string][]) {
    rotateDefaultSelect.append(el("option", { value }, label));
  }
  const rotateDefaultCustom = input({ type: "number", min: "1", max: "36500", inputmode: "numeric" });
  if (vaultDefault === null || vaultDefault === 0) rotateDefaultSelect.value = "never";
  else if (ROTATE_DEFAULT_PRESETS.includes(String(vaultDefault))) {
    rotateDefaultSelect.value = String(vaultDefault);
  } else {
    rotateDefaultSelect.value = "custom";
    rotateDefaultCustom.value = String(vaultDefault);
  }
  const rotateDefaultCustomField = field("Custom default period (days)", rotateDefaultCustom);
  const applyRotateDefault = async (days: number | null) => {
    session.setDefaultRotateDays(days);
    await persist();
    renderUnlocked();
  };
  rotateDefaultSelect.addEventListener("change", async () => {
    rotateDefaultCustomField.classList.toggle(
      "hidden", rotateDefaultSelect.value !== "custom");
    if (rotateDefaultSelect.value === "never") await applyRotateDefault(null);
    else if (rotateDefaultSelect.value !== "custom") {
      await applyRotateDefault(Number(rotateDefaultSelect.value));
    }
  });
  rotateDefaultCustom.addEventListener("change", async () => {
    const days = Number(rotateDefaultCustom.value);
    if (Number.isInteger(days) && days >= 1) await applyRotateDefault(days);
  });
  rotateDefaultCustomField.classList.toggle(
    "hidden", rotateDefaultSelect.value !== "custom");
  panel.append(
    field("Password change reminders (vault default)", rotateDefaultSelect,
      "Passwords are due for a change this long after they were set, unless an entry has its own period."),
    rotateDefaultCustomField,
  );

  const actions = el("div", { class: "action-stack" });
  actions.append(
    button("Download my vault file", async () => {
      const ok = await exportFile(VAULT_FILENAME, state.storedBytes ?? (await session.serialize()));
      status.textContent = ok
        ? "Vault file saved. Keep it somewhere safe — it's encrypted, but it's the only copy on some setups."
        : "Save cancelled.";
    }),
    button(session.hasRecovery() ? "Replace my recovery phrase" : "Set up a recovery phrase",
      () => renderPhraseSetup(session, false)),
    button("Change master password", () => renderChangeMaster()),
    button("Appearance — colours and skins", () => renderAppearance()),
    button("Import passwords from a browser file", () => renderImportCsv()),
    button("Export passwords as a readable file (CSV)", () => renderExportCsv()),
  );

  if (syncFolderSupported()) {
    actions.append(
      button(state.syncHandle ? "Save vault to my sync folder now" : "Use a sync folder (e.g. your cloud drive)",
        async () => {
          if (!state.syncHandle) {
            const handle = await chooseSyncFolder();
            if (!handle) return;
            state.syncHandle = handle;
            await store.setSyncDirHandle(handle);
          }
          const ok = await syncFolderPush(state.syncHandle, state.storedBytes ?? (await session.serialize()));
          status.textContent = ok
            ? "Vault saved to your folder. Your cloud app carries the encrypted file; MyKey itself never connects anywhere."
            : "Couldn't write to that folder. It may need permission again.";
        }),
      button("Load the vault from my sync folder", async () => {
        if (!state.syncHandle) {
          status.textContent = "Choose a sync folder first (button above).";
          return;
        }
        const bytes = await syncFolderPull(state.syncHandle);
        if (!bytes) {
          status.textContent = "No vault file in that folder yet.";
          return;
        }
        if (!window.confirm(
          "Replace the vault on this device with the folder's copy? Passwords added here since the last save to the folder will be lost.",
        )) return;
        state.storedBytes = bytes;
        await store.setVaultBytes(bytes);
        lock("Vault replaced from your sync folder. Unlock to open it.");
      }),
    );
  } else if (isNativeApp()) {
    // The Android app has no folder picker (the WebView does not
    // provide one), so sync here is an honest file flow through
    // the user's own cloud app — labelled as exactly that.
    actions.append(
      button("Load a vault file from my cloud app", async () => {
        const picked = await pickFile();
        if (!picked) return;
        const pickedId = vaultIdOf(picked.bytes);
        if (!pickedId) {
          status.textContent = "That file isn't a MyKey vault file.";
          return;
        }
        const message =
          pickedId === session.vaultId
            ? "Replace the vault on this phone with this file's copy? Do this when the file is the newer one — changes made here since then will be lost."
            : "This file holds a different vault from the one open now. Replace the vault on this phone with it? The vault open now stays safe in its own file, wherever you saved it.";
        if (!window.confirm(message)) return;
        state.storedBytes = picked.bytes;
        await store.setVaultBytes(picked.bytes);
        lock("Vault loaded from the file. Unlock to open it.");
      }),
    );
    panel.append(el("p", { class: "hint" },
      "Syncing in the app works through files: “Download my vault file” saves the encrypted vault into your cloud app (Drive, iCloud, and the like), and “Load a vault file” brings a newer copy back. MyKey itself never connects anywhere — your cloud app carries the file."));
  } else {
    panel.append(el("p", { class: "hint" },
      "Folder sync needs a desktop Chromium browser. In this browser, use “Download my vault file”, carry it with your cloud app, and choose “Open a vault file” on the other device."));
  }

  if (isNativeApp()) {
    const toggle = button(
      state.settings.deviceSlotEnabled ? "Turn off fingerprint unlock" : "Turn on fingerprint unlock",
      async () => {
        if (state.settings.deviceSlotEnabled) {
          session.removeSlot(DEVICE_SLOT_ID);
          await removeDeviceWrapKey();
          state.settings = { ...state.settings, deviceSlotEnabled: false };
          await store.setSettings(state.settings);
          await persist();
          renderUnlocked();
          return;
        }
        if (!(await biometricAvailable())) {
          status.textContent = "No fingerprint or face unlock is set up on this phone.";
          return;
        }
        const wrapKey = randomBytes(32);
        await session.addWrappedSlot(DEVICE_SLOT_ID, wrapKey);
        await storeDeviceWrapKey(b64encode(wrapKey));
        wrapKey.fill(0);
        state.settings = { ...state.settings, deviceSlotEnabled: true };
        await store.setSettings(state.settings);
        await persist();
        renderUnlocked();
      },
    );
    actions.append(toggle);
  }

  panel.append(actions, status);
  panel.append(
    el("p", { class: "hint" }, `${BRAND.productName} ${"2.1.0"} · ${BRAND.vendor}`),
    el("p", { class: "hint" }, BRAND.attribution),
  );
  return panel;
}

function renderChangeMaster(): void {
  const session = state.session!;
  const root = el("section", { class: "screen" });
  root.append(el("h2", {}, "Change master password"));
  const error = el("p", { class: "alert alert-error hidden", role: "alert" });
  const pw = input({ type: "password", autocomplete: "new-password" });
  const pw2 = input({ type: "password", autocomplete: "new-password" });
  const form = el("form", { class: "form" });
  form.append(field("New master password (at least 12 characters)", pw),
    field("Type it again", pw2), error);
  const submit = button("Change password", async () => {}, "primary");
  submit.type = "submit";
  form.append(submit, button("Cancel", () => renderUnlocked()));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    error.classList.add("hidden");
    if (pw.value !== pw2.value) {
      error.textContent = "The two passwords don't match.";
      error.classList.remove("hidden");
      return;
    }
    try {
      await session.changeMaster(pw.value);
      await persist();
      renderUnlocked();
    } catch (err) {
      error.textContent = errorText(err);
      error.classList.remove("hidden");
    }
  });
  root.append(form);
  render(root);
  armAutoLock();
}

// ------------------------------------------------------------------
// Appearance (skins)
// ------------------------------------------------------------------

function skinSwatches(choiceId: string): HTMLElement {
  const wrap = el("span", { class: "swatches" });
  const dot = (colour: string) => {
    const d = el("span", { class: "swatch" });
    d.style.background = colour;
    return d;
  };
  if (choiceId === "device") {
    wrap.append(
      dot(THEMES[DEVICE_LIGHT]!.tokens.brand),
      dot(THEMES[DEVICE_DARK]!.tokens.brand),
    );
    return wrap;
  }
  const def = THEMES[choiceId]!;
  wrap.append(dot(def.tokens.paper), dot(def.tokens.brand), dot(def.tokens.accent));
  if (choiceId === "chakra") {
    const band = el("span", { class: "swatch-band" });
    band.style.background =
      `linear-gradient(90deg, ${CHAKRA_SPECTRUM.join(", ")})`;
    wrap.append(band);
  }
  return wrap;
}

function renderAppearance(): void {
  const root = el("section", { class: "screen" });
  root.append(el("h2", {}, "Appearance"));
  root.append(
    el("p", { class: "lede" },
      "Pick the colours that feel right to you. Tapping a skin changes the whole app at once, so you can see it before you decide. Your choice is saved on this device only."),
  );
  const list = el("div", { class: "skin-list" });
  const draw = () => {
    list.replaceChildren();
    const choice = currentThemeChoice();
    const option = (id: string, name: string, blurb: string) => {
      const active = choice === id;
      const btn = el("button", {
        type: "button",
        class: "skin-option",
        "aria-pressed": active ? "true" : "false",
      });
      btn.append(
        skinSwatches(id),
        el("span", { class: "skin-text" },
          el("span", { class: "skin-name" }, name),
          el("span", { class: "skin-blurb" }, blurb)),
      );
      if (active) btn.append(el("span", { class: "skin-now" }, "In use"));
      btn.addEventListener("click", () => {
        chooseTheme(id);
        draw();
      });
      return btn;
    };
    list.append(option(
      "device",
      "Use device settings",
      "Follows this device: light or dark, as the device itself is set.",
    ));
    for (const id of THEME_ORDER) {
      const def = THEMES[id]!;
      list.append(option(id, def.name, def.blurb));
    }
  };
  draw();
  root.append(
    list,
    el("div", { class: "action-stack" },
      button("Back", () => renderUnlocked())),
  );
  render(root);
  armAutoLock();
}

// ------------------------------------------------------------------
// CSV import (browser exports) + export
// ------------------------------------------------------------------

function renderImportCsv(): void {
  const session = state.session!;
  const root = el("section", { class: "screen" });
  root.append(el("h2", {}, "Import passwords"));
  root.append(
    el("p", { class: "lede" },
      "Bring in passwords you saved in a browser. First export them from that browser into a file (in Chrome: Settings, then Passwords, then Export). Then pick the file here. It is read on this device only and never sent anywhere — everything lands inside your encrypted vault."),
  );
  const error = el("p", { class: "alert alert-error hidden", role: "alert" });
  const work = el("div", {});
  root.append(error, work);

  let entries: ImportRecord[] = [];
  let skippedEmpty = 0;
  let policyInputs: HTMLInputElement[] = [];

  const showError = (msg: string) => {
    error.textContent = msg;
    error.classList.remove("hidden");
  };

  const chosenPolicy = (): ConflictPolicy =>
    (policyInputs.find((i) => i.checked)?.value ?? "skip") as ConflictPolicy;

  const showPreview = (formatLabel: string) => {
    work.replaceChildren();
    policyInputs = [];
    const cls = classifyImport(entries, session.listEntries());
    const box = el("div", { class: "card" });
    box.append(el("h3", {}, "Check before importing"));
    box.append(el("p", {}, `This looks like ${formatLabel}.`));
    box.append(el("p", {},
      `${entries.length} password${entries.length === 1 ? "" : "s"} in the file` +
      (skippedEmpty ? `, with ${skippedEmpty} blank row${skippedEmpty === 1 ? "" : "s"} skipped.` : ".")));
    box.append(el("p", {}, `${cls.fresh.length} are new to your vault.`));
    if (cls.duplicates.length) {
      box.append(el("p", {},
        `${cls.duplicates.length} are already in your vault with the same password — those are skipped.`));
    }
    if (cls.conflicts.length) {
      box.append(el("p", {},
        `${cls.conflicts.length} match a name already in your vault, but with a different password. What should happen to those?`));
      const group = el("div", { class: "form", role: "radiogroup",
        "aria-label": "What to do when a password differs" });
      for (const [value, label] of [
        ["skip", "Keep the password already in my vault"],
        ["overwrite", "Use the password from the file instead"],
        ["keep_both", "Keep both — add the file's as a second entry"],
      ] as const) {
        const radio = el("input", { type: "radio", name: "conflict-policy", value }) as HTMLInputElement;
        if (value === "skip") radio.checked = true;
        policyInputs.push(radio);
        group.append(el("label", { class: "radio" }, radio, ` ${label}`));
      }
      box.append(group);
    }
    const doImport = button("Add them to my vault", async () => {
      const stats = await session.importEntries(entries, chosenPolicy());
      await persist();
      const parts = [`Added ${stats.added} new password${stats.added === 1 ? "" : "s"}.`];
      if (stats.overwritten) parts.push(`Replaced ${stats.overwritten} with the file's version.`);
      if (stats.keptBoth) parts.push(`Kept both copies of ${stats.keptBoth}.`);
      if (stats.skippedConflicts) parts.push(`Left ${stats.skippedConflicts} unchanged, as you chose.`);
      if (stats.duplicates) parts.push(`Skipped ${stats.duplicates} that were already here.`);
      work.replaceChildren(
        el("div", { class: "card" },
          el("h3", {}, "Import finished"),
          el("p", {}, parts.join(" ")),
          el("p", { class: "hint" },
            "You can delete the exported file now — everything you need is inside your vault."),
          button("See my passwords", () => renderUnlocked(), "primary")),
      );
    }, "primary");
    if (cls.fresh.length + cls.conflicts.length === 0) doImport.disabled = true;
    box.append(
      doImport,
      button("Choose a different file", () => renderImportCsv()),
      button("Cancel", () => renderUnlocked()),
    );
    work.append(box);
  };

  const showMapping = (headers: string[], rows: Array<Record<string, string>>) => {
    work.replaceChildren();
    const box = el("div", { class: "card" });
    box.append(el("h3", {}, "Which column is which?"));
    box.append(el("p", {},
      "We couldn't place this file on our own. Tell us which column holds each thing, and we'll take it from there."));
    const guesses: Record<string, string[]> = {
      service: ["name", "Title", "service", "Service", "site", "Site"],
      username: ["username", "Username", "login_username", "user", "email"],
      password: ["password", "Password", "login_password"],
      url: ["url", "URL", "login_uri", "website", "Website"],
      notes: ["notes", "Notes", "note"],
      totp_secret: ["totp", "login_totp", "OTPAuth", "totp_secret"],
    };
    const selects = new Map<string, HTMLSelectElement>();
    const form = el("div", { class: "form" });
    for (const [key, label] of [
      ["service", "Service or app name (needed)"],
      ["username", "Username or email"],
      ["password", "Password (needed)"],
      ["url", "Website"],
      ["notes", "Notes"],
      ["totp_secret", "Sign-in code secret"],
    ] as const) {
      const select = el("select", { class: "text-input" }) as HTMLSelectElement;
      select.append(el("option", { value: "" }, "Not in the file"));
      for (const h of headers) select.append(el("option", { value: h }, h));
      const guess = guesses[key]!.find((g) => headers.includes(g));
      if (guess) select.value = guess;
      selects.set(key, select);
      form.append(field(label, select));
    }
    box.append(form);
    box.append(
      button("Preview the import", () => {
        const mapping: GenericMapping = {};
        for (const [key, select] of selects) {
          if (select.value) {
            (mapping as Record<string, string>)[key] = select.value;
          }
        }
        if (!mapping.service || !mapping.password) {
          showError("Pick the columns for the service name and the password — those two are needed.");
          return;
        }
        error.classList.add("hidden");
        const mapped = genericMapEntries(rows, mapping);
        entries = mapped.filter((e) => e.service || e.username);
        skippedEmpty = mapped.length - entries.length;
        showPreview("a file you matched by hand");
      }, "primary"),
      button("Cancel", () => renderUnlocked()),
    );
    work.append(box);
  };

  const start = el("div", { class: "action-stack" });
  start.append(
    button("Choose the exported file", async () => {
      error.classList.add("hidden");
      const picked = await pickFile(".csv,text/csv,text/plain");
      if (!picked) return;
      const text = utf8Decode(picked.bytes);
      let parsed;
      try {
        parsed = parseImportCsv(text);
      } catch {
        showError("That file doesn't look like a password export — it needs a first row naming its columns.");
        return;
      }
      if (parsed.format === "generic") {
        let rows: Array<Record<string, string>>;
        try {
          rows = rowsFromCsv(text).rows;
        } catch {
          showError("That file doesn't look like a password export.");
          return;
        }
        showMapping(parsed.headers, rows);
        return;
      }
      const totalRows = rowsFromCsv(text).rows.length;
      entries = parsed.entries;
      skippedEmpty = Math.max(0, totalRows - entries.length);
      showPreview(
        parsed.format === "chromium"
          ? "a Chrome-family export (Chrome, Edge, Brave, and similar)"
          : "a Firefox export",
      );
    }, "primary"),
    button("Back", () => renderUnlocked()),
  );
  work.append(start);
  render(root);
  armAutoLock();
}

function renderExportCsv(): void {
  const session = state.session!;
  const root = el("section", { class: "screen" });
  root.append(el("h2", {}, "Export passwords as a readable file"));
  const entries = session.listEntries();
  const status = el("p", { class: "status", "aria-live": "polite" });

  const warning = el("div", { class: "warning-panel" });
  warning.append(
    el("h3", {}, "Please read this first"),
    el("p", {},
      "This makes a file (a CSV) that lists your passwords in plain words. It is NOT encrypted — anyone who opens it can read every password in your vault."),
    el("p", {},
      "Only make this file if you are moving your passwords somewhere else. Delete it as soon as you are finished, and empty the trash afterwards."),
  );
  root.append(warning);

  const confirmBox = el("input", { type: "checkbox" }) as HTMLInputElement;
  const exportBtn = button("Export the readable file", async () => {
    const csv = exportCsv(session.listEntries());
    const ok = await exportFile(EXPORT_FILENAME, utf8Encode(csv), "text/csv");
    status.textContent = ok
      ? `Saved as ${EXPORT_FILENAME}. Delete it as soon as you are done with it.`
      : "Save cancelled — no file was made.";
  }, "primary");
  exportBtn.disabled = true;
  confirmBox.addEventListener("change", () => {
    exportBtn.disabled = !confirmBox.checked || entries.length === 0;
  });
  if (entries.length === 0) {
    status.textContent = "Your vault has no passwords to export yet.";
  }
  root.append(
    el("label", { class: "checkbox" }, confirmBox,
      " I understand this file shows my passwords in plain text."),
    el("div", { class: "action-stack" },
      exportBtn,
      button("Cancel", () => renderUnlocked())),
    status,
  );
  render(root);
  armAutoLock();
}

// ------------------------------------------------------------------
// Boot + global behaviour
// ------------------------------------------------------------------

export async function boot(): Promise<void> {
  state.settings = await store.getSettings();
  state.storedBytes = (await store.getVaultBytes()) ?? null;
  state.syncHandle = (await store.getSyncDirHandle().catch(() => undefined)) ?? null;

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden" && state.session && state.settings.lockOnHide) {
      lock();
    }
  });
  for (const evt of ["pointerdown", "keydown"]) {
    document.addEventListener(evt, () => {
      if (state.session) armAutoLock();
    }, { passive: true });
  }
  await renderLocked();
}
