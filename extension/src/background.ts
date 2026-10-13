// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core (extension session
// orchestration). It is NOT licensed under Apache 2.0, MIT, or any
// other open licence. No patent licence is granted by this file;
// all patent rights are expressly reserved. See LICENSING.md.

/** Background core: owns the host session and every cache.
 *
 * Cache discipline (the leak suite asserts all of it):
 * - Match results cached per tab hold METADATA ONLY (service,
 *   username, flags) — never passwords, never TOTP secrets.
 * - A fill fetches the secret from the host at click time, hands it
 *   straight to the content script in that tab, and keeps no copy.
 * - A captured login awaiting the human's Save decision lives in
 *   this object's memory ONLY — never in extension storage — and
 *   dies on lock, disconnect, decline, or after two minutes.
 * - When the host reports "locked" (or the pipe closes), every
 *   cache is wiped immediately.
 */

import {
  ChannelError,
  HostRefused,
  HostSession,
  type FrameTransport,
} from "./channel.js";
import {
  CLIPBOARD_ALARM,
  clearClipboardNow,
  clampClipboardSeconds,
  runClipboardClear,
  type ClipboardDeps,
} from "./clipboard.js";
import { generatePassword } from "./generator.js";
import { loadOrCreateIdentity, pinnedHost } from "./keys.js";
import { NativeTransport } from "./native.js";
import { originOfUrl } from "./origin.js";
import type { ExtTab, WebExtApi } from "./webext.js";

export interface MatchMeta {
  id: string;
  service: string;
  username: string;
  has_totp: boolean;
  fill_subdomains: boolean;
}

export interface PendingSaveView {
  origin: string;
  username: string;
  mode: "new" | "update";
}

interface PendingSave extends PendingSaveView {
  token: string;
  tabId: number;
  password: string;
  entryId: string | null;
  at: number;
}

const PENDING_SAVE_TTL_MS = 120_000;

export interface BackgroundDeps {
  api: WebExtApi;
  createTransport?: (api: WebExtApi) => FrameTransport;
  /** Clipboard access for background contexts (Firefox event page).
   * Chromium service workers have none — there the offscreen
   * document runs the clear (see offscreen.ts). */
  clipboardDeps?: ClipboardDeps;
  now?: () => number;
}

export class BackgroundCore {
  private api: WebExtApi;
  private createTransport: (api: WebExtApi) => FrameTransport;
  private clipboardDeps?: ClipboardDeps;
  private now: () => number;

  private session: HostSession | null = null;
  private connecting: Promise<HostSession> | null = null;
  private unlocked = false;
  private scopes: string[] = [];
  private clipboardSeconds = 60;
  private matchByTab = new Map<number, { origin: string; matches: MatchMeta[] }>();
  private entryOrigin = new Map<string, string>();
  private pendingSave: PendingSave | null = null;
  private armedTabs = new Set<number>();

  constructor(deps: BackgroundDeps) {
    this.api = deps.api;
    this.createTransport =
      deps.createTransport ?? ((api) => new NativeTransport(api));
    this.clipboardDeps = deps.clipboardDeps;
    this.now = deps.now ?? (() => Date.now());
  }

  // -- session ---------------------------------------------------------------

  async status(): Promise<{
    paired: boolean;
    connected: boolean;
    unlocked: boolean;
    scopes: string[];
    clipboardSeconds: number;
    pendingSave: PendingSaveView | null;
  }> {
    const host = await pinnedHost(this.api.storage.local);
    return {
      paired: host !== null,
      connected: this.session !== null,
      unlocked: this.unlocked,
      scopes: this.scopes,
      clipboardSeconds: this.clipboardSeconds,
      pendingSave: this.pendingSaveView(),
    };
  }

  private pendingSaveView(): PendingSaveView | null {
    if (!this.pendingSave) return null;
    if (this.now() - this.pendingSave.at > PENDING_SAVE_TTL_MS) {
      this.pendingSave = null;
      return null;
    }
    const { origin, username, mode } = this.pendingSave;
    return { origin, username, mode };
  }

  async connect(): Promise<void> {
    if (this.session) return;
    if (!this.connecting) {
      this.connecting = this.doConnect().finally(() => {
        this.connecting = null;
      });
    }
    await this.connecting;
  }

  private async doConnect(): Promise<HostSession> {
    const identity = await loadOrCreateIdentity(this.api.storage.local);
    const host = await pinnedHost(this.api.storage.local);
    if (!host) {
      throw new HostRefused(
        "unpaired",
        "this browser is not paired yet — open the extension options to pair",
      );
    }
    const transport = this.createTransport(this.api);
    const session = await HostSession.connect(transport, {
      extensionId: this.api.runtime.id,
      privateKey: identity.privateKey,
      pinnedHostPub: host.publicKey,
    });
    this.session = session;
    this.unlocked = session.ack.unlocked;
    this.scopes = session.ack.scopes;
    session.onClose(() => this.handleDisconnect());
    await this.refreshStatus();
    return session;
  }

  private async refreshStatus(): Promise<void> {
    if (!this.session) return;
    try {
      const res = await this.session.call("status");
      this.unlocked = Boolean(res.unlocked);
      this.clipboardSeconds = clampClipboardSeconds(
        Number(res.clipboard_clear_seconds ?? 60),
      );
      if (Array.isArray(res.scopes)) this.scopes = res.scopes as string[];
    } catch {
      /* status is advisory; the next real call will surface errors */
    }
  }

  private handleDisconnect(): void {
    this.session = null;
    this.unlocked = false;
    this.wipeCaches();
  }

  private wipeCaches(): void {
    this.matchByTab.clear();
    this.entryOrigin.clear();
    this.pendingSave = null;
  }

  /** Every host call funnels through here so a "locked" refusal
   * wipes local state the moment the desktop locks. */
  private async callHost(
    kind: string,
    fields: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    await this.connect();
    if (!this.session) throw new ChannelError("not connected");
    try {
      return await this.session.call(kind, fields);
    } catch (err) {
      if (err instanceof HostRefused && err.code === "locked") {
        this.unlocked = false;
        this.wipeCaches();
      }
      if (err instanceof ChannelError) {
        this.handleDisconnect();
      }
      throw err;
    }
  }

  // -- vault actions -----------------------------------------------------------

  async unlock(password: string): Promise<{ entries: number }> {
    const res = await this.callHost("unlock", { password });
    this.unlocked = true;
    this.wipeCaches();
    return { entries: Number(res.entries ?? 0) };
  }

  async lock(): Promise<void> {
    try {
      if (this.session) await this.session.call("lock");
    } catch {
      /* locking is best-effort over the wire; local wipe is certain */
    }
    this.unlocked = false;
    this.wipeCaches();
    if (this.clipboardDeps) {
      await clearClipboardNow(this.clipboardDeps);
    }
  }

  async matches(tab: ExtTab): Promise<{ origin: string | null; matches: MatchMeta[] }> {
    const origin = tab.url ? originOfUrl(tab.url) : null;
    if (!origin || tab.id === undefined) return { origin, matches: [] };
    const res = await this.callHost("match", { origin });
    const matches = (res.matches as MatchMeta[]) ?? [];
    this.matchByTab.set(tab.id, { origin, matches });
    for (const match of matches) this.entryOrigin.set(match.id, origin);
    return { origin, matches };
  }

  private async currentOrigin(tab: ExtTab): Promise<string> {
    const origin = tab.url ? originOfUrl(tab.url) : null;
    if (!origin) {
      throw new HostRefused(
        "bad_origin",
        "this page has no web origin to fill on",
      );
    }
    return origin;
  }

  /** Extension-side origin binding: a fill may only go to the tab
   * origin the entry was matched on. The host re-validates too —
   * this is the second lock on the same door. */
  private async boundOrigin(tab: ExtTab, entryId: string): Promise<string> {
    const origin = await this.currentOrigin(tab);
    const bound = this.entryOrigin.get(entryId);
    if (bound !== undefined && bound !== origin) {
      throw new HostRefused(
        "origin_mismatch",
        "this entry was matched on a different origin — nothing was sent",
      );
    }
    return origin;
  }

  private async injectContent(tabId: number): Promise<void> {
    await this.api.scripting.executeScript({
      target: { tabId, frameIds: [0] },
      files: ["content.js"],
    });
  }

  async fill(tab: ExtTab, entryId: string): Promise<{ username: boolean; password: boolean }> {
    if (tab.id === undefined) throw new ChannelError("tab has no id");
    const origin = await this.boundOrigin(tab, entryId);
    const creds = await this.callHost("fill", { entry_id: entryId, origin });
    await this.injectContent(tab.id);
    const results = await this.api.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [0] },
      func: (username: string, password: string) =>
        (
          window as unknown as {
            __mkContent?: {
              fill: (u: string, p: string) => { username: boolean; password: boolean };
            };
          }
        ).__mkContent?.fill(username, password) ?? {
          username: false,
          password: false,
        },
      args: [String(creds.username ?? ""), String(creds.password ?? "")],
    });
    const first = results[0]?.result as
      | { username: boolean; password: boolean }
      | undefined;
    if (!first?.password) {
      throw new HostRefused(
        "no_form",
        "no login form was found on this page — open the site's sign-in page and try again",
      );
    }
    return first;
  }

  /** Returns the code too, so the popup can offer Copy when the
   * page has no code field to fill. */
  async totp(
    tab: ExtTab,
    entryId: string,
  ): Promise<{ code: string; filled: boolean }> {
    if (tab.id === undefined) throw new ChannelError("tab has no id");
    const origin = await this.boundOrigin(tab, entryId);
    const res = await this.callHost("totp", { entry_id: entryId, origin });
    const code = String(res.code ?? "");
    let filled = false;
    try {
      await this.injectContent(tab.id);
      const results = await this.api.scripting.executeScript({
        target: { tabId: tab.id, frameIds: [0] },
        func: (value: string) =>
          (
            window as unknown as {
              __mkContent?: { fillTotp: (c: string) => boolean };
            }
          ).__mkContent?.fillTotp(value) ?? false,
        args: [code],
      });
      filled = Boolean(results[0]?.result);
    } catch {
      filled = false;
    }
    return { code, filled };
  }

  /** Copy path: the popup owns the clipboard, so the secret is
   * returned to it (same extension, never to a page). */
  async copyCredentials(
    tab: ExtTab,
    entryId: string,
  ): Promise<{ username: string; password: string }> {
    const origin = await this.boundOrigin(tab, entryId);
    const res = await this.callHost("fill", { entry_id: entryId, origin });
    return {
      username: String(res.username ?? ""),
      password: String(res.password ?? ""),
    };
  }

  async setSubdomains(
    tab: ExtTab,
    entryId: string,
    value: boolean,
  ): Promise<MatchMeta[]> {
    await this.callHost("set_entry_pref", {
      entry_id: entryId,
      fill_subdomains: value,
    });
    const { matches } = await this.matches(tab);
    return matches;
  }

  generate(length = 20): string {
    return generatePassword(length);
  }

  // -- save capture --------------------------------------------------------------

  async armTab(tabId: number): Promise<void> {
    this.armedTabs.add(tabId);
    try {
      await this.injectContent(tabId);
    } catch {
      /* non-web tab: arming simply does nothing there */
    }
  }

  async onTabUpdated(tabId: number, status: string | undefined): Promise<void> {
    if (status !== "complete") return;
    if (this.armedTabs.has(tabId)) {
      try {
        await this.injectContent(tabId);
      } catch {
        this.armedTabs.delete(tabId);
      }
    }
    // A pending save whose prompt could not be shown on the
    // post-login page gets another chance on each completed load.
    if (this.pendingSave && this.pendingSave.tabId === tabId) {
      await this.showPendingPrompt(tabId);
    }
  }

  async onCaptured(
    tabId: number,
    captured: { origin: string; username: string; password: string },
  ): Promise<void> {
    if (!this.session || !this.unlocked) {
      // Never stash a secret while locked: the candidate dies here.
      return;
    }
    let check: Record<string, unknown>;
    try {
      check = await this.callHost("save_check", { ...captured });
    } catch {
      return;
    }
    if (check.status === "exists_same") return;
    const token = Array.from(crypto.getRandomValues(new Uint8Array(12)))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    this.pendingSave = {
      token,
      tabId,
      origin: captured.origin,
      username: captured.username,
      password: captured.password,
      entryId:
        typeof check.entry_id === "string" ? check.entry_id : null,
      mode: check.status === "exists_diff" ? "update" : "new",
      at: this.now(),
    };
    await this.showPendingPrompt(tabId);
  }

  private async showPendingPrompt(tabId: number): Promise<void> {
    const pending = this.pendingSave;
    if (!pending) return;
    let hostLabel = pending.origin;
    try {
      hostLabel = new URL(pending.origin).hostname.replace(/^www\./, "");
    } catch {
      /* keep the origin string */
    }
    try {
      await this.injectContent(tabId);
      await this.api.scripting.executeScript({
        target: { tabId, frameIds: [0] },
        func: (
          token: string,
          spec: { mode: "new" | "update"; service: string; username: string },
        ) =>
          (
            window as unknown as {
              __mkContent?: {
                showSavePrompt: (
                  t: string,
                  s: { mode: "new" | "update"; service: string; username: string },
                ) => void;
              };
            }
          ).__mkContent?.showSavePrompt(token, spec),
        args: [
          pending.token,
          { mode: pending.mode, service: hostLabel, username: pending.username },
        ],
      });
    } catch {
      await this.api.action.setBadgeText({ text: "1", tabId });
      await this.api.action.setBadgeBackgroundColor({ color: "#2f7fd0" });
    }
  }

  async saveChoice(
    token: string,
    accepted: boolean,
  ): Promise<{ saved: boolean; changed: string[] }> {
    const pending = this.pendingSave;
    if (!pending || pending.token !== token) {
      return { saved: false, changed: [] };
    }
    this.pendingSave = null;
    try {
      await this.api.action.setBadgeText({ text: "", tabId: pending.tabId });
    } catch {
      /* badge is cosmetic */
    }
    if (!accepted) return { saved: false, changed: [] };
    const fields: Record<string, unknown> = {
      origin: pending.origin,
      username: pending.username,
      password: pending.password,
    };
    if (pending.entryId) fields.entry_id = pending.entryId;
    const res = await this.callHost("save_commit", fields);
    return {
      saved: Boolean(res.saved),
      changed: Array.isArray(res.changed) ? (res.changed as string[]) : [],
    };
  }

  async pendingSaveAction(
    accepted: boolean,
  ): Promise<{ saved: boolean; changed: string[] }> {
    if (!this.pendingSave) return { saved: false, changed: [] };
    return this.saveChoice(this.pendingSave.token, accepted);
  }

  // -- clipboard alarm -------------------------------------------------------------

  async onClipboardAlarm(): Promise<void> {
    if (this.api.offscreen?.createDocument) {
      // Chromium: the service worker cannot touch the clipboard;
      // the offscreen document runs the clear pass.
      try {
        if (!(await this.api.offscreen.hasDocument())) {
          await this.api.offscreen.createDocument({
            url: "offscreen.html",
            reasons: [this.api.offscreen.Reason.CLIPBOARD],
            justification:
              "Clear copied passwords from the clipboard after the set time.",
          });
        }
        await this.api.runtime.sendMessage({ type: "mk-clipboard-clear-pass" });
      } catch {
        /* if the platform refuses, the popup-side timer remains */
      }
      return;
    }
    if (this.clipboardDeps) {
      await runClipboardClear(this.clipboardDeps);
    }
  }

  // -- inspection (tests + the options page's honest status) ---------------------

  inspect(): {
    sessionOpen: boolean;
    unlocked: boolean;
    matchTabs: number;
    boundEntries: number;
    pendingSave: boolean;
    armedTabs: number;
  } {
    return {
      sessionOpen: this.session !== null,
      unlocked: this.unlocked,
      matchTabs: this.matchByTab.size,
      boundEntries: this.entryOrigin.size,
      pendingSave: this.pendingSave !== null,
      armedTabs: this.armedTabs.size,
    };
  }
}
