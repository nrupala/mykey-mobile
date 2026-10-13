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

// This client's own identities — mirrors of the desktop engine's
// devices.DeviceIdentity (MKDEV card / MKDEVKEYS key file) and
// pairings.PairingTargetIdentity (MKPAIR payload / MKPAIRKEYS key
// file). Same field names, same fingerprints, so a card or payload
// made here enrolls on the desktop and vice versa.
//
// A device identity lets THIS client receive backup-package slots
// like any enrolled device. The private keys live only in local
// app storage (the IndexedDB store; the Android app's sandboxed
// storage), never inside the vault — the vault holds only the
// public card, enrolled by the human. Same honesty rule as the
// desktop: local storage protection, not an OS keystore claim.

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { b64decode, b64encode, nowSeconds, randomBytes, uuidHex } from "./encoding.js";
import { deviceFingerprint } from "./backup.js";
import {
  pairingFingerprint,
  type PairingPayload,
  type PairingType,
} from "./pairings.js";

export interface DeviceCard {
  format: string;
  version: number;
  device_id: string;
  label: string;
  x25519_pub: string;
  ed25519_pub: string;
  fingerprint: string;
}

/** The registry record verify_card produces on the desktop. */
export interface DeviceRecord {
  device_id: string;
  label: string;
  x25519_pub: string;
  ed25519_pub: string;
  fingerprint: string;
  enrolled_at?: number;
  revoked_at?: number | null;
}

export class DeviceIdentity {
  constructor(
    readonly deviceId: string,
    readonly label: string,
    readonly createdAt: number, // epoch seconds
    private readonly xPriv: Uint8Array,
    private readonly ePriv: Uint8Array,
  ) {}

  static generate(label: string): DeviceIdentity {
    return new DeviceIdentity(uuidHex(), label, nowSeconds(), randomBytes(32), randomBytes(32));
  }

  get xPub(): Uint8Array {
    return x25519.getPublicKey(this.xPriv);
  }

  get ePub(): Uint8Array {
    return ed25519.getPublicKey(this.ePriv);
  }

  get xPrivateRaw(): Uint8Array {
    return this.xPriv;
  }

  get fingerprint(): string {
    return deviceFingerprint(this.xPub, this.ePub);
  }

  sign(data: Uint8Array): Uint8Array {
    return ed25519.sign(data, this.ePriv);
  }

  card(): DeviceCard {
    return {
      format: "MKDEV",
      version: 1,
      device_id: this.deviceId,
      label: this.label,
      x25519_pub: b64encode(this.xPub),
      ed25519_pub: b64encode(this.ePub),
      fingerprint: this.fingerprint,
    };
  }

  /** Desktop key-file JSON (MKDEVKEYS v1) — one portable shape. */
  serialize(): string {
    return JSON.stringify(
      {
        format: "MKDEVKEYS",
        version: 1,
        device_id: this.deviceId,
        label: this.label,
        created_at: this.createdAt,
        x25519_priv: b64encode(this.xPriv),
        x25519_pub: b64encode(this.xPub),
        ed25519_priv: b64encode(this.ePriv),
        ed25519_pub: b64encode(this.ePub),
        fingerprint: this.fingerprint,
      },
      null,
      2,
    );
  }

  static parse(text: string): DeviceIdentity {
    let data: Record<string, unknown>;
    try {
      data = JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new Error("This device's saved keys aren't readable. Remove them and set the device up again.");
    }
    if (data.format !== "MKDEVKEYS" || data.version !== 1) {
      throw new Error("This device's saved keys have an unsupported format.");
    }
    const ident = new DeviceIdentity(
      String(data.device_id ?? ""),
      String(data.label ?? ""),
      Number(data.created_at ?? 0),
      b64decode(String(data.x25519_priv ?? "")),
      b64decode(String(data.ed25519_priv ?? "")),
    );
    if (ident.xPriv.length !== 32 || ident.ePriv.length !== 32) {
      throw new Error("This device's saved keys are damaged. Remove them and set the device up again.");
    }
    if (
      b64encode(ident.xPub) !== data.x25519_pub ||
      b64encode(ident.ePub) !== data.ed25519_pub ||
      data.fingerprint !== ident.fingerprint
    ) {
      throw new Error("This device's saved keys don't match their public keys — the file was edited. Remove them and set the device up again.");
    }
    return ident;
  }
}

/** Verify an MKDEV card (mirror devices.verify_card): fingerprints
 *  are always recomputed — a card whose stated fingerprint does not
 *  match its keys is refused, never trusted. */
export function verifyDeviceCard(card: Record<string, unknown>): DeviceRecord {
  if (card?.format !== "MKDEV" || card?.version !== 1) {
    throw new Error("not a device card (format/version not recognized)");
  }
  const deviceId = String(card.device_id ?? "");
  if (deviceId.length !== 32 || !/^[0-9a-fA-F]+$/.test(deviceId)) {
    throw new Error("device card has a malformed device id");
  }
  let xPub: Uint8Array, ePub: Uint8Array;
  try {
    xPub = b64decode(String(card.x25519_pub ?? ""));
    ePub = b64decode(String(card.ed25519_pub ?? ""));
  } catch {
    throw new Error("device card keys are malformed");
  }
  if (xPub.length !== 32 || ePub.length !== 32) {
    throw new Error("device card keys have the wrong length");
  }
  const fingerprint = deviceFingerprint(xPub, ePub);
  if (card.fingerprint !== fingerprint) {
    throw new Error("device card fingerprint does not match its keys — refuse it");
  }
  return {
    device_id: deviceId,
    label: String(card.label ?? ""),
    x25519_pub: b64encode(xPub),
    ed25519_pub: b64encode(ePub),
    fingerprint,
  };
}

// ---------------------------------------------------------------------
// Pairing target identity (MKPAIR / MKPAIRKEYS) — the credential a
// target holds. This client plays the target role when a folder or
// export target is set up here; enrollment always happens on the
// vault side from the payload, after the human compares the
// fingerprint.
// ---------------------------------------------------------------------

export class PairingTargetIdentity {
  constructor(
    readonly targetId: string,
    readonly label: string,
    readonly targetType: PairingType,
    readonly createdAt: number, // epoch seconds
    private readonly xPriv: Uint8Array,
  ) {}

  static generate(targetType: PairingType, label: string): PairingTargetIdentity {
    return new PairingTargetIdentity(uuidHex(), label, targetType, nowSeconds(), randomBytes(32));
  }

  get xPub(): Uint8Array {
    return x25519.getPublicKey(this.xPriv);
  }

  get xPrivateRaw(): Uint8Array {
    return this.xPriv;
  }

  get fingerprint(): string {
    return pairingFingerprint(this.xPub);
  }

  payload(): PairingPayload {
    return {
      format: "MKPAIR",
      version: 1,
      target_id: this.targetId,
      label: this.label,
      type: this.targetType,
      x25519_pub: b64encode(this.xPub),
      fingerprint: this.fingerprint,
    };
  }

  serialize(): string {
    return JSON.stringify(
      {
        format: "MKPAIRKEYS",
        version: 1,
        target_id: this.targetId,
        label: this.label,
        type: this.targetType,
        created_at: this.createdAt,
        x25519_priv: b64encode(this.xPriv),
        x25519_pub: b64encode(this.xPub),
        fingerprint: this.fingerprint,
      },
      null,
      2,
    );
  }

  static parse(text: string): PairingTargetIdentity {
    let data: Record<string, unknown>;
    try {
      data = JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new Error("The saved pairing keys aren't readable.");
    }
    if (data.format !== "MKPAIRKEYS" || data.version !== 1) {
      throw new Error("The saved pairing keys have an unsupported format.");
    }
    const ident = new PairingTargetIdentity(
      String(data.target_id ?? ""),
      String(data.label ?? ""),
      data.type as PairingType,
      Number(data.created_at ?? 0),
      b64decode(String(data.x25519_priv ?? "")),
    );
    if (ident.xPriv.length !== 32) throw new Error("The saved pairing keys are damaged.");
    if (b64encode(ident.xPub) !== data.x25519_pub || data.fingerprint !== ident.fingerprint) {
      throw new Error("The saved pairing keys don't match their public key — the file was edited.");
    }
    return ident;
  }
}
