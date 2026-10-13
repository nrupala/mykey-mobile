// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// Copyright (c) 2026 2351485 ALBERTA INC.
//
// Integration against the REAL desktop native host (Python,
// nrupala/mykey): the TypeScript client channel must interoperate
// byte-for-byte, and the raw pipe bytes are grepped for every
// fixture secret (leak gates 1, 2, 5, 6 against the real host).
//
// Needs the desktop repo: MYKEY_DESKTOP_DIR env (CI checks out
// nrupala/mykey beside this repo and sets it). Skips cleanly when
// the desktop checkout is absent so the pure-TS suites still run.

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  HostRefused,
  HostSession,
  type FrameTransport,
} from "../src/channel.js";
import { b64decode } from "../../src/vault/encoding.js";
import { ALL_SECRETS, GITHUB, MASTER } from "./support/fixtures.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const EXT_ROOT = join(HERE, "..");
const PYTHON = process.env.MYKEY_PYTHON ?? "python3";

function desktopDir(): string | null {
  const candidates = [
    process.env.MYKEY_DESKTOP_DIR,
    join(EXT_ROOT, "..", "..", "mykey-py"),
    join(EXT_ROOT, "..", "mykey-py"),
  ].filter(Boolean) as string[];
  for (const dir of candidates) {
    if (existsSync(join(dir, "native_host.py"))) return dir;
  }
  return null;
}

const DESKTOP = desktopDir();

interface FixtureConfig {
  master: string;
  vault: string;
  store: string;
  extension_id: string;
  ext_priv_b64: string;
  host_pub_b64: string;
  host_fingerprint: string;
}

class StdioTransport implements FrameTransport {
  proc: ChildProcessWithoutNullStreams;
  wire = Buffer.alloc(0);
  private frameCbs: ((frame: Record<string, unknown>) => void)[] = [];
  private closeCbs: (() => void)[] = [];
  private buffer = Buffer.alloc(0);

  constructor(desktop: string, store: string) {
    this.proc = spawn(PYTHON, [join(desktop, "native_host.py")], {
      env: { ...process.env, MYKEY_EXT_STORE: store },
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.proc.stdout.on("data", (chunk: Buffer) => {
      this.wire = Buffer.concat([this.wire, chunk]);
      this.buffer = Buffer.concat([this.buffer, chunk]);
      for (;;) {
        if (this.buffer.length < 4) break;
        const len = this.buffer.readUInt32LE(0);
        if (this.buffer.length < 4 + len) break;
        const frame = JSON.parse(
          this.buffer.subarray(4, 4 + len).toString("utf8"),
        ) as Record<string, unknown>;
        this.buffer = this.buffer.subarray(4 + len);
        this.frameCbs.forEach((cb) => cb(frame));
      }
    });
    this.proc.on("exit", () => this.closeCbs.forEach((cb) => cb()));
  }

  post(frame: Record<string, unknown>): void {
    const body = Buffer.from(JSON.stringify(frame), "utf8");
    const head = Buffer.alloc(4);
    head.writeUInt32LE(body.length, 0);
    const packet = Buffer.concat([head, body]);
    this.wire = Buffer.concat([this.wire, packet]);
    this.proc.stdin.write(packet);
  }

  onFrame(cb: (frame: Record<string, unknown>) => void): void {
    this.frameCbs.push(cb);
  }

  onClose(cb: () => void): void {
    this.closeCbs.push(cb);
  }

  close(): void {
    this.proc.stdin.end();
    this.proc.kill();
  }

  wireText(): string {
    return this.wire.toString("latin1");
  }
}

describe.skipIf(!DESKTOP)("real desktop host integration", () => {
  let config: FixtureConfig;
  let workdir: string;

  beforeAll(async () => {
    workdir = mkdtempSync(join(tmpdir(), "mkext-itest-"));
    await new Promise<void>((resolve, reject) => {
      const proc = spawn(
        PYTHON,
        [
          join(EXT_ROOT, "scripts", "make_fixture_vault.py"),
          "--desktop",
          DESKTOP as string,
          "--out",
          workdir,
        ],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      let err = "";
      proc.stderr.on("data", (c: Buffer) => (err += c.toString()));
      proc.on("exit", (code) =>
        code === 0 ? resolve() : reject(new Error(err)),
      );
    });
    config = JSON.parse(
      readFileSync(join(workdir, "config.json"), "utf8"),
    ) as FixtureConfig;
  }, 120_000);

  afterAll(() => {
    // workdir holds only fixture material; left in tmp for the OS.
  });

  async function connectSession(): Promise<{
    session: HostSession;
    transport: StdioTransport;
  }> {
    const transport = new StdioTransport(DESKTOP as string, config.store);
    const session = await HostSession.connect(transport, {
      extensionId: config.extension_id,
      privateKey: b64decode(config.ext_priv_b64),
      pinnedHostPub: b64decode(config.host_pub_b64),
    });
    return { session, transport };
  }

  it("gates 1+2+5: full flow over the real pipe, no plaintext, lock works", async () => {
    const { session, transport } = await connectSession();
    try {
      await expect(
        session.call("unlock", { password: "not-the-password" }),
      ).rejects.toBeInstanceOf(HostRefused);
      await session.call("unlock", { password: MASTER });
      const matched = await session.call("match", {
        origin: "https://github.com",
      });
      const matches = matched.matches as { id: string; username: string }[];
      expect(matches).toHaveLength(1);
      expect(matches[0]?.username).toBe(GITHUB.username);
      const entryId = matches[0]?.id as string;
      const filled = await session.call("fill", {
        entry_id: entryId,
        origin: "https://github.com",
      });
      expect(filled.password).toBe(GITHUB.password);
      const totp = await session.call("totp", {
        entry_id: entryId,
        origin: "https://github.com",
      });
      expect(String(totp.code)).toMatch(/^\d{6}$/);
      for (const evil of [
        "https://github.com.evil.com",
        "https://evil-github.com",
        "http://github.com",
        "https://github.com:8443",
        "https://login.github.com",
      ]) {
        const res = await session.call("match", { origin: evil });
        expect(res.matches, evil).toEqual([]);
      }
      await session.call("lock");
      await expect(
        session.call("match", { origin: "https://github.com" }),
      ).rejects.toMatchObject({ code: "locked" });
      // GATE 1 against the real pipe bytes:
      const wire = transport.wireText();
      expect(wire).toContain('"ct"');
      for (const secret of [...ALL_SECRETS, String(totp.code)]) {
        expect(wire.includes(secret), `wire leaked ${secret}`).toBe(false);
      }
    } finally {
      transport.close();
    }
  }, 60_000);

  it("gate 6: a revoked pairing is refused at hello", async () => {
    await new Promise<void>((resolve, reject) => {
      const code = [
        "import sys",
        `sys.path.insert(0, ${JSON.stringify(DESKTOP)})`,
        "import extpair",
        `s = extpair.ExtensionHostStore.load(${JSON.stringify(config.store)})`,
        `s.revoke(${JSON.stringify(config.extension_id)})`,
        "print('revoked')",
      ].join("\n");
      const proc = spawn(PYTHON, ["-c", code], {
        stdio: ["ignore", "pipe", "pipe"],
      });
      let err = "";
      proc.stderr.on("data", (c: Buffer) => (err += c.toString()));
      proc.on("exit", (c) =>
        c === 0 ? resolve() : reject(new Error(err)),
      );
    });
    const transport = new StdioTransport(DESKTOP as string, config.store);
    try {
      await expect(
        HostSession.connect(transport, {
          extensionId: config.extension_id,
          privateKey: b64decode(config.ext_priv_b64),
          pinnedHostPub: b64decode(config.host_pub_b64),
        }),
      ).rejects.toMatchObject({ code: "pairing_refused" });
    } finally {
      transport.close();
    }
  }, 60_000);
});
