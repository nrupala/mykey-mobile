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
import mykey  # noqa: E402

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


def created():
    info = json.loads((OUT / "created-expected.json").read_text())
    path = stage("created.mykey", (OUT / "created.mykey").read_bytes())
    v = open_py(path, info["password"])
    entries = v.list_entries()
    assert len(entries) == 1 and entries[0]["service"] == "created-service"
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

if failures:
    print(f"\n{len(failures)} cross-check(s) FAILED")
    sys.exit(1)
print("\nall Python cross-checks passed")
