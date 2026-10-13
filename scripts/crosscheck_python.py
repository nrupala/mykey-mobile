# Cross-check: files written by the TypeScript client, opened by the
# PYTHON implementation (the interoperability gate in reverse).
# Not shipped to users; run by `npm run test:cross` and in CI.
#
#   MYKEY_PY_DIR=/path/to/mykey python scripts/crosscheck_python.py

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY_SRC = os.environ.get("MYKEY_PY_DIR")
if not PY_SRC:
    raise SystemExit("set MYKEY_PY_DIR to the mykey (Python) repo checkout")
sys.path.insert(0, PY_SRC)

import agents  # noqa: E402
import backup_pkg  # noqa: E402
import devices  # noqa: E402
import mykey  # noqa: E402
import pairings as pairings_mod  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
OUT = FIX / "out"
expected = json.loads((FIX / "expected.json").read_text())
PASSWORD = expected["password"]
TMP = Path(tempfile.mkdtemp(prefix="mykey-cross-"))

failures = []


def check(name, fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        failures.append(f"{name}: {type(exc).__name__}: {exc}")
        print(f"FAIL {name}: {type(exc).__name__}: {exc}")
    else:
        print(f"ok   {name}")


def stage(name, data: bytes) -> str:
    p = TMP / name
    p.write_bytes(data)
    return str(p)


def open_py(path, password=PASSWORD):
    v = mykey.MyKey(password, vault_file=str(path))
    v.unlock()
    return v


def view(e):
    return {
        "service": e["service"], "username": e["username"],
        "password": e["password"], "url": e["url"], "notes": e["notes"],
        "totp_secret": e["totp_secret"], "tags": e["tags"],
        "favourite": e["favourite"],
    }


def expect_entries(name, path, password=PASSWORD):
    v = open_py(path, password)
    got = sorted((view(e) for e in v.list_entries()), key=lambda e: e["service"])
    want = sorted((view(e) for e in expected["entries"]),
                  key=lambda e: e["service"])
    assert got == want, f"entries differ:\n got={got}\nwant={want}"


check("python opens the TS-resaved fixture vault",
      lambda: expect_entries("resaved", stage(
          "resaved.mykey", (OUT / "resaved.mykey").read_bytes())))


def modified():
    v = open_py(stage("modified.mykey", (OUT / "modified.mykey").read_bytes()))
    entries = {e["service"]: e for e in v.list_entries()}
    assert entries["github"]["password"] == "ts-changed-password-1", entries["github"]
    assert entries["tsadded"]["password"] == "ts-added-password-1"
    assert len(entries) == 4


check("python sees the TS edits and the TS-added entry", modified)


def rotation_survives_ts_resave():
    rot = expected["rotation"]
    v = open_py(stage("resaved.mykey", (OUT / "resaved.mykey").read_bytes()))
    assert v.vault_settings()["default_rotate_days"] == \
        rot["default_rotate_days"]
    entries = {e["service"]: e for e in v.list_entries()}
    for service, want in rot["entries"].items():
        e = entries[service]
        assert e["password_set_at"] == rot["password_set_at"], (service, e)
        assert e["rotate_days"] == want["rotate_days"], (service, e)


check("python sees rotation fields intact after a TS resave",
      rotation_survives_ts_resave)


def rotation_clock_reset_by_ts():
    rot = expected["rotation"]
    v = open_py(stage("modified.mykey", (OUT / "modified.mykey").read_bytes()))
    entries = {e["service"]: e for e in v.list_entries()}
    # The TS client changed github's password: its clock must have
    # reset off the fixture value, and its override must survive.
    assert entries["github"]["password_set_at"] > rot["password_set_at"]
    assert entries["github"]["rotate_days"] == 90
    # The untouched entry keeps its fixture state exactly.
    assert entries["bank"]["password_set_at"] == rot["password_set_at"]
    assert entries["bank"]["rotate_days"] is None


check("a TS password change resets the clock Python reads",
      rotation_clock_reset_by_ts)


def created():
    info = json.loads((OUT / "created-expected.json").read_text())
    path = stage("created.mykey", (OUT / "created.mykey").read_bytes())
    v = open_py(path, info["password"])
    entries = v.list_entries()
    assert len(entries) == 1 and entries[0]["service"] == "created-service"
    # A TS-created vault carries the standard 180-day default in its
    # encrypted core settings, readable by the Python engine.
    assert v.vault_settings()["default_rotate_days"] == 180
    assert entries[0]["totp_secret"] == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    # the TS-set recovery phrase must unlock in Python too
    v2 = mykey.MyKey.recover(str(path), info["recovery_phrase"],
                             "Recovered-Master-2026")
    assert v2.list_entries()[0]["username"] == "created-user"


check("python opens the TS-created vault by password AND phrase", created)


def agent_still_works():
    token = expected["agent"]["token"]
    path = stage("modified.mykey", (OUT / "modified.mykey").read_bytes())
    session = agents.open_agent_session(str(path), token)
    got = session.get("github")
    assert got["service"] == "github", got
    try:
        session.get("bank")
    except (agents.AgentScopeError, agents.AgentAuthError):
        pass
    else:
        raise AssertionError("agent read an out-of-scope entry after TS save")


check("agent bundle rebuilt by TS still enforces scope in Python",
      agent_still_works)


def device_slot_preserved():
    # The raw-wrap slot the TS client adds for Android must survive a
    # Python open (unknown slots are preserved verbatim).
    s = (OUT / "created.mykey").read_text()
    assert "recovery" in s


check("TS-created vault carries a recovery slot", device_slot_preserved)


# ---------------------------------------------------------------------
# Blob wave: the TS-exported MKBAK v2 package must open in Python
# via recovery (phrase + backup code), via the device key, and via
# the pairing key — and phrase-only must be REFUSED (two-factor).
# ---------------------------------------------------------------------

def _ts_export_info():
    return json.loads((OUT / "ts-export.json").read_text())


def _stage_pkg():
    return stage("ts-export.mykeybak",
                 (OUT / "ts-export.mykeybak").read_bytes())


def ts_export_recovery_two_factor():
    info = _ts_export_info()
    pkg = _stage_pkg()
    try:
        backup_pkg.import_package(
            pkg, str(TMP / "imp-none.mykey"),
            recovery_phrase=expected["phrase"],
            expect_fingerprint=info["source_fingerprint"])
    except backup_pkg.BackupRefused:
        pass
    else:
        raise AssertionError(
            "phrase-only import of a TS v2 package was not refused")
    result = backup_pkg.import_package(
        pkg, str(TMP / "imp-rec.mykey"),
        recovery_phrase=expected["phrase"],
        backup_code=info["backup_code"],
        expect_fingerprint=info["source_fingerprint"])
    assert result["via"] == "recovery", result
    assert result["package_version"] == 2 and result["legacy"] is False
    v = open_py(str(TMP / "imp-rec.mykey"))
    assert len(v.list_entries()) == 3


check("python imports the TS v2 package via phrase + backup code "
      "(and refuses phrase-only)", ts_export_recovery_two_factor)


def ts_export_device():
    info = _ts_export_info()
    pkg = _stage_pkg()
    keys = stage("ts-device-keys.json",
                 (OUT / "ts-device-keys.json").read_bytes())
    os.chmod(keys, 0o600)
    ident = devices.DeviceIdentity.load(keys)
    result = backup_pkg.import_package(
        pkg, str(TMP / "imp-dev.mykey"), identity=ident,
        expect_fingerprint=info["source_fingerprint"])
    assert result["via"] == f"device:{ident.device_id}", result


check("python imports the TS v2 package via the device key",
      ts_export_device)


def ts_export_pairing():
    import base64
    info = _ts_export_info()
    pkg = _stage_pkg()
    priv = base64.b64decode(info["pairing_priv_b64"])
    result = backup_pkg.import_package(
        pkg, str(TMP / "imp-pair.mykey"), pairing_priv=priv,
        expect_fingerprint=info["source_fingerprint"])
    assert result["via"] == f"pairing:{info['pairing_target_id']}", result


check("python imports the TS v2 package via the pairing key",
      ts_export_pairing)


def ts_paired_registry():
    info = _ts_export_info()
    v = open_py(stage("paired.mykey", (OUT / "paired.mykey").read_bytes()))
    rec = v._pairings[info["pairing_target_id"]]
    assert rec["fingerprint"] == info["pairing_fingerprint"], rec
    assert rec["enabled"] and not rec["revoked_at"]
    assert info["pairing_target_id"] in pairings_mod.active_pairings(
        v, scope="export")


check("python reads the TS-enrolled pairing registry from the vault core",
      ts_paired_registry)

if failures:
    print(f"\n{len(failures)} cross-check(s) FAILED")
    sys.exit(1)
print("\nall Python cross-checks passed")
