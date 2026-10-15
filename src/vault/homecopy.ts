// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core. It is NOT licensed
// under Apache 2.0, MIT, or any other open licence. No patent
// licence is granted by this file; all patent rights are expressly
// reserved. See LICENSING.md.

/** The vault's home (owner's model, 2026-10-14): the vault is a
 * file, and MyKey is its opener. On Android the canonical copy of
 * the vault lives OUTSIDE the app, in a folder the user chooses
 * (MyKey/vault.mykey under it); the copy inside the app is only a
 * working cache, so the app still opens when the folder cannot be
 * reached. Uninstalling the app then cannot take the vault with
 * it — the file alone opens nothing without the master password.
 *
 * Reconciliation discipline (the sync anti-rollback rule, applied
 * to two copies): the service remembers the digest of BOTH copies
 * at the last moment they agreed. A copy that moved since then is
 * the newer one. If only the home file moved, it wins and
 * refreshes the cache. If only the cache moved, it is written out.
 * If BOTH moved, that is a conflict: both are preserved and the
 * user is asked — an older copy never silently replaces a newer
 * one, and nothing is ever overwritten on a guess.
 *
 * This module is the decision logic and the service that applies
 * it. The storage mechanism (Android SAF) sits behind the
 * HomeCopyAdapter interface, so every decision here is unit-tested
 * with a fake adapter. The web client has no adapter: no home
 * copy is offered there, exactly as the UI must never offer what
 * it cannot do. */

import { sha256 } from "@noble/hashes/sha2.js";
import { utf8Decode } from "./encoding.js";

export const HOME_DIR_NAME = "MyKey";
export const HOME_FILE_NAME = "vault.mykey";

/** Bridge to the platform's folder storage. All byte arrays are
 * the encrypted vault file itself — ciphertext only, always. */
export interface HomeCopyAdapter {
  /** Ask the user for a folder; resolves null on cancel. A
   * successful pick is remembered by the platform side. */
  pickFolder(): Promise<{ folderName: string } | null>;
  /** The granted folder's state, or null when no folder is
   * currently granted (never picked, or the grant is gone). */
  folderInfo(): Promise<HomeFolderInfo | null>;
  readHomeFile(): Promise<Uint8Array | null>;
  writeHomeFile(bytes: Uint8Array): Promise<void>;
  writePreservedFile(bytes: Uint8Array, name: string): Promise<void>;
  forgetFolder(): Promise<void>;
}

export interface HomeFolderInfo {
  folderName: string;
  hasFile: boolean;
  modifiedAt: number | null; // epoch ms
  size: number | null;
}

/** Device-local setup for the home copy. The folder grant itself
 * lives on the platform side; this records what the user chose
 * and which vault the home belongs to. */
export interface MirrorConfig {
  enabled: boolean;
  folderName: string | null;
  vaultId: string | null;
  offeredForVaultId: string | null;
}

/** Reconciliation bookkeeping: digests of both copies at the last
 * moment they agreed, plus the user-visible record (last write,
 * last error, a one-line notice for the next unlock, and any
 * unresolved conflict). Digests and counts only — never content. */
export interface MirrorBook {
  vaultId: string | null;
  cacheDigest: string | null;
  homeDigest: string | null;
  lastWriteAt: number | null;
  lastError: string | null;
  lastErrorAt: number | null;
  pendingNotice: string | null;
  foreignHome: boolean;
  conflict: { cacheDigest: string; homeDigest: string; detectedAt: number } | null;
}

export interface MirrorStateStore {
  getConfig(): Promise<MirrorConfig>;
  setConfig(c: MirrorConfig): Promise<void>;
  getBook(): Promise<MirrorBook>;
  setBook(b: MirrorBook): Promise<void>;
}

export function defaultMirrorConfig(): MirrorConfig {
  return { enabled: false, folderName: null, vaultId: null, offeredForVaultId: null };
}

export function defaultMirrorBook(): MirrorBook {
  return {
    vaultId: null,
    cacheDigest: null,
    homeDigest: null,
    lastWriteAt: null,
    lastError: null,
    lastErrorAt: null,
    pendingNotice: null,
    foreignHome: false,
    conflict: null,
  };
}

export function digestHex(bytes: Uint8Array): string {
  return [...sha256(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** The vault id sits in the file's plaintext header (it is an
 * identifier, not a secret), so copies can be told apart — and a
 * foreign vault recognised — before anything is unlocked. */
export function vaultIdOfBytes(bytes: Uint8Array | null): string | null {
  if (!bytes) return null;
  try {
    const parsed = JSON.parse(utf8Decode(bytes)) as { vault_id?: unknown };
    return typeof parsed.vault_id === "string" ? parsed.vault_id : null;
  } catch {
    return null;
  }
}

/** Where a superseded copy is preserved in the home folder: next
 * to the home file, under a dated name, never deleted by the app. */
export function preservedFileName(date: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return (
    `vault-conflict-${date.getFullYear()}${p(date.getMonth() + 1)}${p(date.getDate())}` +
    `-${p(date.getHours())}${p(date.getMinutes())}${p(date.getSeconds())}.mykey`
  );
}

export type ReconcileDecision =
  | { kind: "no-home" }
  | { kind: "in-sync" }
  | { kind: "home-newer" }
  | { kind: "cache-newer" }
  | { kind: "conflict" }
  | { kind: "different-vault" };

/** The reconciliation decision, pure. Bookkeeping from a
 * different vault is ignored (treated as no agreement point). */
export function decideReconcile(args: {
  cacheDigest: string;
  cacheVaultId: string | null;
  homeDigest: string | null;
  homeVaultId: string | null;
  book: MirrorBook;
}): ReconcileDecision {
  const { cacheDigest, homeDigest } = args;
  if (homeDigest === null) return { kind: "no-home" };
  if (args.homeVaultId && args.cacheVaultId && args.homeVaultId !== args.cacheVaultId) {
    return { kind: "different-vault" };
  }
  const bookApplies = !args.book.vaultId || !args.cacheVaultId || args.book.vaultId === args.cacheVaultId;
  const agreedCache = bookApplies ? args.book.cacheDigest : null;
  const agreedHome = bookApplies ? args.book.homeDigest : null;
  if (cacheDigest === homeDigest) return { kind: "in-sync" };
  const cacheMoved = cacheDigest !== agreedCache;
  const homeMoved = homeDigest !== agreedHome;
  if (homeMoved && !cacheMoved) return { kind: "home-newer" };
  if (cacheMoved && !homeMoved) return { kind: "cache-newer" };
  if (!cacheMoved && !homeMoved) return { kind: "in-sync" }; // unreachable given digests differ; kept for clarity
  return { kind: "conflict" };
}

export type HomeStatusKind =
  | "unsupported"
  | "not-setup"
  | "off"
  | "ok"
  | "error"
  | "conflict"
  | "different-vault";

function formatUpdated(ms: number): string {
  const d = new Date(ms);
  const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const today = new Date();
  const sameDay =
    d.getFullYear() === today.getFullYear() &&
    d.getMonth() === today.getMonth() &&
    d.getDate() === today.getDate();
  if (sameDay) return `today at ${time}`;
  return `${d.toLocaleDateString([], { day: "numeric", month: "short" })} at ${time}`;
}

/** The Settings status line, in plain words, derived from the
 * recorded state. Pure: the caller gathers the inputs. */
export function deriveHomeStatus(input: {
  supported: boolean;
  configured: boolean;
  config: MirrorConfig;
  book: MirrorBook;
}): { kind: HomeStatusKind; line: string } {
  const { config, book } = input;
  const folder = config.folderName ?? "your folder";
  if (!input.supported) return { kind: "unsupported", line: "" };
  if (!input.configured) {
    return {
      kind: "not-setup",
      line: "Not set up. Your vault's only copy is inside the app — if the app is removed, the vault goes with it.",
    };
  }
  if (book.conflict) {
    return {
      kind: "conflict",
      line: "Two different copies of your vault exist — one in the app, one in its home folder. You will be asked which to keep when you unlock.",
    };
  }
  if (book.foreignHome) {
    return {
      kind: "different-vault",
      line: `The folder “${folder}” holds a different vault's home file. MyKey has written nothing there.`,
    };
  }
  if (!config.enabled) {
    return {
      kind: "off",
      line: `Turned off. The copy in “${folder}” is no longer updated. It stays in the folder until you delete it yourself.`,
    };
  }
  if (book.lastError) {
    return {
      kind: "error",
      line: `The home copy could not be updated (${book.lastError}). Your vault is safe in the app — the copy is retried on the next save.`,
    };
  }
  return {
    kind: "ok",
    line: book.lastWriteAt
      ? `Home: “${folder}” · updated ${formatUpdated(book.lastWriteAt)}`
      : `Home: “${folder}”. Your vault file is kept there, updated on every save.`,
  };
}

export type SetupProbe =
  | { kind: "empty"; folderName: string }
  | { kind: "found"; folderName: string; bytes: Uint8Array }
  | { kind: "same"; folderName: string; bytes: Uint8Array }
  | { kind: "same-vault-diff"; folderName: string; bytes: Uint8Array }
  | { kind: "different-vault"; folderName: string; bytes: Uint8Array };

function errText(err: unknown): string {
  const msg = err instanceof Error ? err.message : "unknown error";
  return msg.length > 120 ? `${msg.slice(0, 117)}…` : msg;
}

/** Applies the home-copy model on top of an adapter + state
 * store. Every method is failure-honest and none of them throw:
 * a home-copy problem must never block the vault itself. */
export class HomeCopyService {
  constructor(
    private readonly adapter: HomeCopyAdapter | null,
    private readonly states: MirrorStateStore,
  ) {}

  supported(): boolean {
    return this.adapter !== null;
  }

  async config(): Promise<MirrorConfig> {
    return this.states.getConfig();
  }

  async book(): Promise<MirrorBook> {
    return this.states.getBook();
  }

  /** The first-run offer is made once per vault. */
  async offerNeeded(vaultId: string): Promise<boolean> {
    if (!this.adapter) return false;
    const cfg = await this.states.getConfig();
    if (cfg.enabled && cfg.vaultId === vaultId) return false;
    return cfg.offeredForVaultId !== vaultId;
  }

  async markOffered(vaultId: string): Promise<void> {
    const cfg = await this.states.getConfig();
    await this.states.setConfig({ ...cfg, offeredForVaultId: vaultId });
  }

  /** Consume the one-line notice recorded for the next unlock. */
  async takePendingNotice(): Promise<string | null> {
    const book = await this.states.getBook();
    if (!book.pendingNotice) return null;
    await this.states.setBook({ ...book, pendingNotice: null });
    return book.pendingNotice;
  }

  private async syncBook(vaultId: string | null, digest: string): Promise<void> {
    const book = await this.states.getBook();
    await this.states.setBook({
      ...book,
      vaultId,
      cacheDigest: digest,
      homeDigest: digest,
      foreignHome: false,
      conflict: null,
      lastError: null,
    });
  }

  private async recordFailure(err: unknown): Promise<void> {
    const book = await this.states.getBook();
    await this.states.setBook({
      ...book,
      lastError: errText(err),
      lastErrorAt: Date.now(),
      pendingNotice:
        "Your vault's home copy could not be updated. Your vault is safe in the app — see Settings.",
    });
  }

  /** After the device copy was written (every persist, and on
   * lock). Writes the same ciphertext to the home file. Never
   * throws; a failure is recorded, never silent. */
  async afterPersist(bytes: Uint8Array): Promise<void> {
    if (!this.adapter) return;
    try {
      const cfg = await this.states.getConfig();
      if (!cfg.enabled) return;
      const vaultId = vaultIdOfBytes(bytes);
      if (cfg.vaultId && vaultId && cfg.vaultId !== vaultId) return; // another vault's home
      const book = await this.states.getBook();
      if (book.foreignHome) return; // hands off until the user resolves it
      if (book.conflict) return; // the conflict owns the home file until resolved
      const digest = digestHex(bytes);
      if (book.cacheDigest === digest && book.homeDigest === digest && !book.lastError) return;
      await this.adapter.writeHomeFile(bytes);
      const fresh = await this.states.getBook();
      await this.states.setBook({
        ...fresh,
        vaultId,
        cacheDigest: digest,
        homeDigest: digest,
        lastWriteAt: Date.now(),
        lastError: null,
      });
    } catch (err) {
      await this.recordFailure(err).catch(() => undefined);
    }
  }

  /** Bytes that just became the device copy from elsewhere (an
   * opened file, a restored package, a folder pull). They become
   * canonical: digests reset to them, and the home file is
   * written too when it is safe (no home yet, or the same
   * vault's home). A different vault's home is never touched. */
  async adopt(bytes: Uint8Array): Promise<void> {
    if (!this.adapter) return;
    try {
      const vaultId = vaultIdOfBytes(bytes);
      const digest = digestHex(bytes);
      const cfg = await this.states.getConfig();
      const book = await this.states.getBook();
      await this.states.setBook({
        ...book,
        vaultId,
        cacheDigest: digest,
        homeDigest: book.homeDigest, // adjusted below when a write lands
        conflict: null,
      });
      if (!cfg.enabled) return;
      if (cfg.vaultId && vaultId && cfg.vaultId !== vaultId) {
        const fresh = await this.states.getBook();
        await this.states.setBook({
          ...fresh,
          pendingNotice:
            "This vault is not the one with a home folder. Its home copy was not touched.",
        });
        return;
      }
      if (book.conflict) {
        // The user is replacing the vault by hand while a
        // conflict is recorded: preserve the home side of the
        // conflict before the adopted copy overwrites it.
        const homeBytes = await this.adapter.readHomeFile().catch(() => null);
        if (homeBytes) {
          await this.adapter.writePreservedFile(homeBytes, preservedFileName(new Date()));
        }
      }
      await this.adapter.writeHomeFile(bytes);
      const fresh = await this.states.getBook();
      await this.states.setBook({
        ...fresh,
        homeDigest: digest,
        lastWriteAt: Date.now(),
        lastError: null,
        foreignHome: false,
      });
    } catch (err) {
      await this.recordFailure(err).catch(() => undefined);
    }
  }

  /** Reconcile the device copy against the home file. Runs at
   * boot, before unlock. Applies the safe outcomes itself
   * (cache-newer is written out; bookkeeping updated); returns
   * what the caller must act on:
   *  - "home-newer": adopt homeBytes as the device copy;
   *  - "conflict": both copies are preserved; ask the user;
   *  - "different-vault": hands off — nothing was written. */
  async reconcile(cacheBytes: Uint8Array): Promise<{
    decision: ReconcileDecision;
    homeBytes: Uint8Array | null;
    folderName: string | null;
  }> {
    const none: ReconcileDecision = { kind: "no-home" };
    if (!this.adapter) return { decision: none, homeBytes: null, folderName: null };
    try {
      const cfg = await this.states.getConfig();
      if (!cfg.enabled) return { decision: none, homeBytes: null, folderName: cfg.folderName };
      const thisVaultId = vaultIdOfBytes(cacheBytes);
      if (cfg.vaultId && thisVaultId && cfg.vaultId !== thisVaultId) {
        // The recorded home belongs to a different vault than
        // the one on this device now — hands off entirely.
        return { decision: none, homeBytes: null, folderName: cfg.folderName };
      }
      const info = await this.adapter.folderInfo();
      if (!info) return { decision: none, homeBytes: null, folderName: cfg.folderName };
      const cacheDigest = digestHex(cacheBytes);
      const cacheVaultId = vaultIdOfBytes(cacheBytes);
      if (!info.hasFile) {
        // The home folder is chosen but empty: the device copy
        // becomes the home file.
        await this.adapter.writeHomeFile(cacheBytes);
        const book = await this.states.getBook();
        await this.states.setBook({
          ...book,
          vaultId: cacheVaultId,
          cacheDigest,
          homeDigest: cacheDigest,
          lastWriteAt: Date.now(),
          lastError: null,
        });
        return { decision: { kind: "cache-newer" }, homeBytes: null, folderName: info.folderName };
      }
      const homeBytes = await this.adapter.readHomeFile();
      if (!homeBytes) return { decision: none, homeBytes: null, folderName: info.folderName };
      const book = await this.states.getBook();
      const decision = decideReconcile({
        cacheDigest,
        cacheVaultId,
        homeDigest: digestHex(homeBytes),
        homeVaultId: vaultIdOfBytes(homeBytes),
        book,
      });
      if (decision.kind === "in-sync") {
        await this.syncBook(cacheVaultId, cacheDigest);
      } else if (decision.kind === "cache-newer") {
        await this.adapter.writeHomeFile(cacheBytes);
        const fresh = await this.states.getBook();
        await this.states.setBook({
          ...fresh,
          vaultId: cacheVaultId,
          cacheDigest,
          homeDigest: cacheDigest,
          lastWriteAt: Date.now(),
          lastError: null,
        });
      } else if (decision.kind === "home-newer") {
        await this.syncBook(cacheVaultId, digestHex(homeBytes));
        const fresh = await this.states.getBook();
        await this.states.setBook({
          ...fresh,
          pendingNotice: `Your vault was updated from its home file in “${info.folderName}”.`,
        });
      } else if (decision.kind === "conflict") {
        const fresh = await this.states.getBook();
        await this.states.setBook({
          ...fresh,
          conflict: {
            cacheDigest,
            homeDigest: digestHex(homeBytes),
            detectedAt: Date.now(),
          },
        });
      } else if (decision.kind === "different-vault") {
        const fresh = await this.states.getBook();
        await this.states.setBook({
          ...fresh,
          foreignHome: true,
          pendingNotice:
            `The folder “${info.folderName}” holds a different vault. ` +
            "MyKey left both copies alone — see Settings.",
        });
      }
      return { decision, homeBytes, folderName: info.folderName };
    } catch (err) {
      await this.recordFailure(err).catch(() => undefined);
      return { decision: none, homeBytes: null, folderName: null };
    }
  }

  /** Resolve a recorded conflict once the user has chosen a
   * copy. The losing copy is preserved in the home folder under
   * a dated name BEFORE anything is overwritten. When the home
   * copy wins, the caller swaps the device copy (this method
   * only aligns the home side + bookkeeping). */
  async resolveConflict(
    winner: "home" | "device",
    cacheBytes: Uint8Array,
    homeBytes: Uint8Array,
  ): Promise<void> {
    if (!this.adapter) return;
    const loser = winner === "home" ? cacheBytes : homeBytes;
    await this.adapter.writePreservedFile(loser, preservedFileName(new Date()));
    if (winner === "device") {
      await this.adapter.writeHomeFile(cacheBytes);
    }
    const winnerBytes = winner === "home" ? homeBytes : cacheBytes;
    await this.syncBook(vaultIdOfBytes(winnerBytes), digestHex(winnerBytes));
  }

  /** The copy inside the app moved on by other means (a sync
   * pull, a manual file load) while a conflict was recorded,
   * so the recorded conflict no longer describes either live
   * copy. Preserve the home side if it is still the recorded
   * one, then re-baseline the bookkeeping on the copies as
   * they now stand and tell the user once. Never throws. */
  async abandonConflict(currentCacheBytes: Uint8Array): Promise<void> {
    if (!this.adapter) return;
    try {
      const cfg = await this.states.getConfig();
      if (!cfg.enabled) return;
      const book = await this.states.getBook();
      if (!book.conflict) return;
      let homeBytes: Uint8Array | null = null;
      try {
        homeBytes = await this.adapter.readHomeFile();
      } catch {
        homeBytes = null;
      }
      if (homeBytes && digestHex(homeBytes) === book.conflict.homeDigest) {
        await this.adapter
          .writePreservedFile(homeBytes, preservedFileName(new Date()))
          .catch(() => undefined);
      }
      const homeVaultId = homeBytes ? vaultIdOfBytes(homeBytes) : null;
      const cacheVaultId = vaultIdOfBytes(currentCacheBytes);
      await this.states.setBook({
        ...book,
        conflict: null,
        vaultId: cacheVaultId ?? book.vaultId,
        cacheDigest: digestHex(currentCacheBytes),
        homeDigest: homeBytes ? digestHex(homeBytes) : book.homeDigest,
        foreignHome: Boolean(
          homeVaultId && cacheVaultId && homeVaultId !== cacheVaultId,
        ),
        pendingNotice:
          "Your vault's copies had both changed. The home folder's older copy was kept as a dated file in the folder, and this device's copy is the one in use.",
      });
    } catch {
      /* bookkeeping must never block the vault */
    }
  }

  /** Fresh-install recovery: a granted folder that still holds a
   * home file (grant survived, or the folder was just picked). */
  async recoveryCandidate(): Promise<{ folderName: string; bytes: Uint8Array } | null> {
    if (!this.adapter) return null;
    try {
      const info = await this.adapter.folderInfo();
      if (!info || !info.hasFile) return null;
      const bytes = await this.adapter.readHomeFile();
      if (!bytes || !vaultIdOfBytes(bytes)) return null;
      return { folderName: info.folderName, bytes };
    } catch {
      return null;
    }
  }

  /** Pick a folder (setup / change / recovery) and report what
   * is already in it, against the current vault when there is
   * one. Resolves null when the user cancels. */
  async pickAndProbe(
    currentBytes: Uint8Array | null,
  ): Promise<(SetupProbe & { bytes: Uint8Array | null }) | null> {
    if (!this.adapter) return null;
    const picked = await this.adapter.pickFolder();
    if (!picked) return null;
    const info = await this.adapter.folderInfo();
    if (!info || !info.hasFile) {
      return { kind: "empty", folderName: picked.folderName, bytes: null };
    }
    const bytes = await this.adapter.readHomeFile();
    if (!bytes) return { kind: "empty", folderName: picked.folderName, bytes: null };
    if (!currentBytes) {
      // No vault on this device yet: any readable vault file is
      // a recovery candidate, whatever vault it is.
      return vaultIdOfBytes(bytes)
        ? { kind: "found", folderName: picked.folderName, bytes }
        : { kind: "empty", folderName: picked.folderName, bytes: null };
    }
    if (digestHex(bytes) === digestHex(currentBytes)) {
      return { kind: "same", folderName: picked.folderName, bytes };
    }
    const homeId = vaultIdOfBytes(bytes);
    const cacheId = vaultIdOfBytes(currentBytes);
    if (homeId && cacheId && homeId !== cacheId) {
      return { kind: "different-vault", folderName: picked.folderName, bytes };
    }
    return { kind: "same-vault-diff", folderName: picked.folderName, bytes };
  }

  /** Finish a setup after the probe. For "same-vault-diff" the
   * caller passes the user's choice; "home" means the folder's
   * copy becomes canonical and this returns its bytes (the
   * caller must drop any open session — its state is the losing
   * copy). Throws on adapter failure so the setup screen can
   * say so; the caller records nothing else. */
  async completeSetup(
    currentBytes: Uint8Array,
    probe: SetupProbe,
    choice?: "home" | "device",
  ): Promise<Uint8Array | null> {
    if (!this.adapter) return null;
    const vaultId = vaultIdOfBytes(currentBytes);
    if (probe.kind === "empty") {
      await this.adapter.writeHomeFile(currentBytes);
      await this.enableFor(probe.folderName, vaultId);
      await this.syncBook(vaultId, digestHex(currentBytes));
      const book = await this.states.getBook();
      await this.states.setBook({ ...book, lastWriteAt: Date.now() });
      return null;
    }
    if (probe.kind === "same") {
      await this.enableFor(probe.folderName, vaultId);
      await this.syncBook(vaultId, digestHex(currentBytes));
      return null;
    }
    if (probe.kind === "different-vault") {
      throw new Error("that folder holds a different vault");
    }
    if (probe.kind === "found") {
      // Only reachable when there is no vault on this device —
      // that is the recovery flow, not setup.
      throw new Error("no vault on this device to set up against");
    }
    // same-vault-diff
    if (choice === "home") {
      await this.enableFor(probe.folderName, vaultIdOfBytes(probe.bytes) ?? vaultId);
      await this.syncBook(vaultIdOfBytes(probe.bytes) ?? vaultId, digestHex(probe.bytes));
      return probe.bytes;
    }
    await this.adapter.writePreservedFile(probe.bytes, preservedFileName(new Date()));
    await this.adapter.writeHomeFile(currentBytes);
    await this.enableFor(probe.folderName, vaultId);
    await this.syncBook(vaultId, digestHex(currentBytes));
    const book = await this.states.getBook();
    await this.states.setBook({ ...book, lastWriteAt: Date.now() });
    return null;
  }

  private async enableFor(folderName: string, vaultId: string | null): Promise<void> {
    const cfg = await this.states.getConfig();
    await this.states.setConfig({
      ...cfg,
      enabled: true,
      folderName,
      vaultId,
      offeredForVaultId: vaultId ?? cfg.offeredForVaultId,
    });
  }

  /** Drop a folder the user picked but setup refused (a
   * different vault's folder): the grant must not linger. */
  async abandonPickedFolder(): Promise<void> {
    try {
      await this.adapter?.forgetFolder();
    } catch {
      /* best effort */
    }
  }

  /** Adopt home bytes that were just opened (the recovery
   * flow): this folder becomes the vault's home. */
  async adoptFromHome(bytes: Uint8Array, folderName: string): Promise<void> {
    const vaultId = vaultIdOfBytes(bytes);
    await this.enableFor(folderName, vaultId);
    await this.syncBook(vaultId, digestHex(bytes));
  }

  async setEnabled(enabled: boolean, currentBytes: Uint8Array | null): Promise<void> {
    const cfg = await this.states.getConfig();
    await this.states.setConfig({ ...cfg, enabled });
    if (enabled && currentBytes) await this.afterPersist(currentBytes);
  }

  /** The Settings status, live: folder name from the platform,
   * everything else from the recorded state. */
  async status(): Promise<{ kind: HomeStatusKind; line: string; folderName: string | null }> {
    const cfg = await this.states.getConfig();
    const book = await this.states.getBook();
    let folderName = cfg.folderName;
    let configured = Boolean(cfg.folderName);
    if (this.adapter) {
      const info = await this.adapter.folderInfo().catch(() => null);
      if (info) {
        folderName = info.folderName;
        configured = true;
      } else if (cfg.folderName) {
        configured = false; // the grant is gone (reinstall / data clear)
      }
    }
    const derived = deriveHomeStatus({
      supported: this.supported(),
      configured,
      config: { ...cfg, folderName },
      book,
    });
    return { ...derived, folderName };
  }
}
