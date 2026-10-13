// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core (vault engine
// helpers). It is NOT licensed under Apache 2.0, MIT, or any other
// open licence. No patent licence is granted by this file; all
// patent rights are expressly reserved. See LICENSING.md.

/** Password age + rotation helpers — a faithful port of the Python
 * engine's rotation_status / rotation_line / rotation_report
 * (mykey.py), so every client shows the same states in the same
 * words. Pure functions: the current time is always injectable.
 */

import { nowSeconds } from "./encoding.js";
import type { VaultEntry } from "./vault.js";

export const ROTATION_DUE_SOON_DAYS = 14;
const DAY = 86400;

export type RotationState = "off" | "unknown" | "ok" | "due_soon" | "overdue";

export interface RotationStatus {
  password_set_at: number | null;
  /** The effective period after override + default resolution. */
  rotate_days: number | null;
  due_at: number | null;
  days_left: number | null;
  state: RotationState;
}

export function rotationStatus(
  entry: Pick<VaultEntry, "password_set_at" | "rotate_days">,
  defaultRotateDays: number | null,
  now?: number,
): RotationStatus {
  const at = now ?? nowSeconds();
  const period = entry.rotate_days ?? defaultRotateDays;
  const psa = entry.password_set_at;
  const status: RotationStatus = {
    password_set_at: psa,
    rotate_days: period,
    due_at: null,
    days_left: null,
    state: "off",
  };
  if (period === null || period <= 0) return status;
  if (psa === null) {
    status.state = "unknown";
    return status;
  }
  const dueAt = psa + period * DAY;
  status.due_at = dueAt;
  status.days_left = Math.floor((dueAt - at) / DAY);
  if (at >= dueAt) status.state = "overdue";
  else if (dueAt - at <= ROTATION_DUE_SOON_DAYS * DAY) status.state = "due_soon";
  else status.state = "ok";
  return status;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function formatDay(ts: number): string {
  const d = new Date(ts * 1000);
  return `${String(d.getDate()).padStart(2, "0")} ${MONTHS[d.getMonth()]} ${d.getFullYear()}`;
}

/** One plain-language line, e.g. "Password set 13 Oct 2026 ·
 * change by 11 Apr 2027" — the same words the desktop shows. */
export function rotationLine(
  entry: Pick<VaultEntry, "password_set_at" | "rotate_days">,
  defaultRotateDays: number | null,
  now?: number,
): string {
  const status = rotationStatus(entry, defaultRotateDays, now);
  if (status.password_set_at === null) return "Password date not recorded";
  const line = `Password set ${formatDay(status.password_set_at)}`;
  if (status.state === "off") return `${line} · change date off`;
  return `${line} · change by ${formatDay(status.due_at!)}`;
}

export interface RotationReportRow extends RotationStatus {
  id: string;
  service: string;
  username: string;
}

const STATE_ORDER: Record<RotationState, number> = {
  overdue: 0, due_soon: 1, unknown: 2, ok: 3, off: 4,
};

/** Whole-vault report, attention first: overdue, due soon,
 * unknown date, ok, rotation off. */
export function rotationReport(
  entries: VaultEntry[],
  defaultRotateDays: number | null,
  now?: number,
): RotationReportRow[] {
  const rows = entries.map((e) => ({
    id: e.id,
    service: e.service,
    username: e.username,
    ...rotationStatus(e, defaultRotateDays, now),
  }));
  rows.sort(
    (a, b) =>
      STATE_ORDER[a.state] - STATE_ORDER[b.state] ||
      a.service.localeCompare(b.service),
  );
  return rows;
}

export function rotationDueCount(
  entries: VaultEntry[],
  defaultRotateDays: number | null,
  now?: number,
): number {
  return entries.filter((e) => {
    const s = rotationStatus(e, defaultRotateDays, now).state;
    return s === "due_soon" || s === "overdue";
  }).length;
}
