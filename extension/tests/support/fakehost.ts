// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// Copyright (c) 2026 2351485 ALBERTA INC.
//
// A fake desktop host for extension-side tests: same wire protocol
// (real channel primitives from src/channel.ts, ack sealed INSIDE
// the hello frame like native_host.py), same message semantics as
// the Python host, fixture vault in memory. The AUTHORITATIVE host
// behaviour is proven against the real Python host in
// host-integration.test.ts and the desktop test suite; this double
// exists so background/content logic can be driven end-to-end (and
// leak-grepped) in pure TypeScript.

import { x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  deriveSessionKeys,
  openMessage,
  sealMessage,
  type FrameTransport,
  type SealedFrame,
} from "../../src/channel.js";
import {
  b64decode,
  b64encode,
  hexEncode,
  randomBytes,
} from "../../../src/vault/encoding.js";
import { ENTRIES, MASTER } from "./fixtures.js";

export interface FixtureEntry {
  id: string;
  service: string;
  username: string;
  password: string;
  url: string;
  totp_secret: string;
}

export type PairingState = "active" | "revoked" | "expired" | "disabled";

type Message = Record<string, unknown>;

export class FakeHost {
  hostPriv: Uint8Array;
  hostPub: Uint8Array;
  pairingState: PairingState = "active";
  scopes = ["fill", "save"];
  unlocked = false;
  entries: FixtureEntry[] = ENTRIES.map((e) => ({ ...e }));
  subdomains = new Set<string>();
  wireLog: string[] = [];
  calls: Message[] = [];
  savedLogins: { origin: string; username: string; password: string }[] = [];

  constructor() {
    this.hostPriv = randomBytes(32);
    this.hostPub = x25519.getPublicKey(this.hostPriv);
  }

  /** One native-messaging pipe per call; all frames recorded.
   * The extension's public key arrives in the hello frame, exactly
   * like the real host sees it. */
  transportFor(extensionId: string): FrameTransport {
    const host = this;
    const listeners: ((frame: Message) => void)[] = [];
    const closeListeners: (() => void)[] = [];
    let sealed: {
      keys: { e2h: Uint8Array; h2e: Uint8Array };
      session: string;
      sendSeq: number;
    } | null = null;
    let closed = false;

    const reply = (frame: Message): void => {
      host.wireLog.push(JSON.stringify(frame));
      listeners.forEach((cb) => cb(frame));
    };

    const transport: FrameTransport = {
      post(frame) {
        host.wireLog.push(JSON.stringify(frame));
        void (async () => {
          if (closed) return;
          if (!sealed) {
            const refusal = host.checkPairing();
            if (refusal) {
              closed = true;
              reply({
                kind: "fatal",
                code: "pairing_refused",
                message: refusal,
              });
              closeListeners.forEach((cb) => cb());
              return;
            }
            const extPub = b64decode(String(frame.ext_pub));
            void extensionId;
            const clientNonce = b64decode(String(frame.client_nonce));
            const serverNonce = randomBytes(32);
            const shared = x25519.getSharedSecret(host.hostPriv, extPub);
            const keys = deriveSessionKeys(shared, clientNonce, serverNonce);
            const both = new Uint8Array(64);
            both.set(clientNonce, 0);
            both.set(serverNonce, 32);
            const session = hexEncode(sha256(both)).slice(0, 32);
            sealed = { keys, session, sendSeq: 0 };
            const ack = await sealMessage(keys.h2e, "h2e", session, 0, {
              kind: "hello_ack",
              protocol: "mykey-ext-v1",
              unlocked: host.unlocked,
              vault_configured: true,
              scopes: host.scopes,
            });
            sealed.sendSeq = 1;
            reply({
              kind: "hello",
              host_pub: b64encode(host.hostPub),
              server_nonce: b64encode(serverNonce),
              session,
              ack,
            });
            return;
          }
          let message: Message;
          try {
            message = await openMessage(
              sealed.keys.e2h,
              "e2h",
              sealed.session,
              frame as unknown as SealedFrame,
            );
          } catch {
            closed = true;
            reply({
              kind: "fatal",
              code: "protocol",
              message: "bad frame",
            });
            return;
          }
          host.calls.push(message);
          const response = host.handle(message);
          if (response) {
            const out = await sealMessage(
              sealed.keys.h2e,
              "h2e",
              sealed.session,
              sealed.sendSeq,
              response,
            );
            sealed.sendSeq += 1;
            reply(out as unknown as Message);
          }
        })();
      },
      onFrame(cb) {
        listeners.push(cb);
      },
      onClose(cb) {
        closeListeners.push(cb);
      },
      close() {
        closed = true;
      },
    };
    return transport;
  }

  private checkPairing(): string | null {
    switch (this.pairingState) {
      case "revoked":
        return "this pairing was revoked on the desktop";
      case "expired":
        return "this pairing has expired";
      case "disabled":
        return "this pairing is disabled on the desktop";
      default:
        return null;
    }
  }

  private entryOrigin(entry: FixtureEntry): string {
    const u = new URL(entry.url);
    const port = u.port ? `:${u.port}` : "";
    return `${u.protocol}//${u.hostname}${port}`;
  }

  private matchEntries(origin: string): FixtureEntry[] {
    const page = new URL(origin);
    return this.entries.filter((entry) => {
      const entryUrl = new URL(entry.url);
      if (page.protocol !== entryUrl.protocol) return false;
      const pagePort =
        page.port || (page.protocol === "https:" ? "443" : "80");
      const entryPort =
        entryUrl.port || (entryUrl.protocol === "https:" ? "443" : "80");
      if (pagePort !== entryPort) return false;
      if (page.hostname === entryUrl.hostname) return true;
      return (
        this.subdomains.has(entry.id) &&
        page.hostname.endsWith(`.${entryUrl.hostname}`)
      );
    });
  }

  private findForOrigin(entryId: string, origin: string): FixtureEntry | null {
    return this.matchEntries(origin).find((e) => e.id === entryId) ?? null;
  }

  private handle(message: Message): Message | null {
    const id = message.id as number;
    const ok = (fields: Message): Message => ({
      kind: "result",
      id,
      ok: true,
      ...fields,
    });
    const err = (code: string, text: string): Message => ({
      kind: "error",
      id,
      ok: false,
      code,
      message: text,
    });
    const lockedGate = (): Message | null =>
      this.unlocked ? null : err("locked", "the vault is locked");
    switch (message.kind) {
      case "ping":
        return ok({});
      case "status":
        return ok({
          unlocked: this.unlocked,
          vault_configured: true,
          scopes: this.scopes,
          clipboard_clear_seconds: 60,
          auto_lock_seconds: 300,
        });
      case "unlock":
        if (message.password === MASTER) {
          this.unlocked = true;
          return ok({ unlocked: true });
        }
        return err("wrong_password", "that password did not open the vault");
      case "lock":
        this.unlocked = false;
        return ok({ unlocked: false });
      case "match": {
        const gate = lockedGate();
        if (gate) return gate;
        return ok({
          matches: this.matchEntries(String(message.origin)).map((e) => ({
            id: e.id,
            service: e.service,
            username: e.username,
            has_totp: Boolean(e.totp_secret),
            fill_subdomains: this.subdomains.has(e.id),
          })),
        });
      }
      case "fill": {
        const gate = lockedGate();
        if (gate) return gate;
        const entry = this.findForOrigin(
          String(message.entry_id),
          String(message.origin),
        );
        if (!entry) return err("no_match", "no entry matches");
        return ok({
          entry_id: entry.id,
          username: entry.username,
          password: entry.password,
        });
      }
      case "totp": {
        const gate = lockedGate();
        if (gate) return gate;
        const entry = this.findForOrigin(
          String(message.entry_id),
          String(message.origin),
        );
        if (!entry?.totp_secret) return err("no_totp", "no code saved");
        return ok({ entry_id: entry.id, code: "123456" });
      }
      case "save_check": {
        const gate = lockedGate();
        if (gate) return gate;
        const existing = this.entries.find(
          (e) =>
            this.entryOrigin(e) === message.origin &&
            e.username === message.username,
        );
        if (!existing) return ok({ status: "new" });
        return ok({
          status:
            existing.password === message.password
              ? "exists_same"
              : "exists_diff",
          entry_id: existing.id,
        });
      }
      case "save_commit": {
        const gate = lockedGate();
        if (gate) return gate;
        this.savedLogins.push({
          origin: String(message.origin),
          username: String(message.username),
          password: String(message.password),
        });
        return ok({
          entry_id: "entry-new",
          saved: true,
          changed: ["new entry"],
        });
      }
      case "set_entry_pref": {
        const gate = lockedGate();
        if (gate) return gate;
        if (message.fill_subdomains) {
          this.subdomains.add(String(message.entry_id));
        } else {
          this.subdomains.delete(String(message.entry_id));
        }
        return ok({
          entry_id: message.entry_id,
          fill_subdomains: Boolean(message.fill_subdomains),
        });
      }
      default:
        return err("bad_request", "unknown message kind");
    }
  }
}
