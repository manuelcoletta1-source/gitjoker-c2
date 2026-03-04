#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import subprocess
from datetime import datetime

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def die(msg: str):
    raise SystemExit(str(msg))


def now_iso_local():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def read_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def append_text(path: str, s: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(s)


def sha256_hex_utf8(s: str) -> str:
    b = s.replace("\r\n", "\n").encode("utf-8")
    return hashlib.sha256(b).hexdigest()


def zero_pad(n: int) -> str:
    return f"{n:06d}"


def openssl_sign_ed25519(privkey_path: str, message_ascii: str) -> str:
    if not os.path.isfile(privkey_path):
        die(f"Missing private key: {privkey_path}")

    payload_path = os.path.join(REPO_ROOT, ".tmp_payload.txt")
    sig_bin_path = os.path.join(REPO_ROOT, ".tmp_sig.bin")

    with open(payload_path, "wb") as f:
        f.write(message_ascii.encode("ascii"))

    cmd = [
        "openssl", "pkeyutl", "-sign",
        "-inkey", privkey_path,
        "-rawin",
        "-in", payload_path,
        "-out", sig_bin_path
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        die("OpenSSL sign failed:\n" + (r.stderr or r.stdout))

    with open(sig_bin_path, "rb") as f:
        sig_b64 = base64.b64encode(f.read()).decode("ascii")

    try:
        os.remove(payload_path)
        os.remove(sig_bin_path)
    except Exception:
        pass

    return sig_b64


def _run(cmd, cwd=None) -> str:
    """
    Fail-closed command runner.
    Important: for Joker-C2, cwd MUST be the hbce-joker-c2-core directory,
    because cli.js resolves policy/ and registry/ from process.cwd().
    """
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if r.returncode != 0:
        die("FAIL_CLOSED: command failed:\n" + " ".join(cmd) + "\n" + (r.stderr or r.stdout))
    return (r.stdout or "").strip()


def _joker_gate(joker_core_dir: str, joker_out_dir: str, request_json_path: str):
    """
    Calls hbce-joker-c2-core/cli.js and returns (status, entry_hash).

    Expected stdout:
      PASS entry_hash=<hex>
      DENY entry_hash=<hex>

    NOTE (critical): run with cwd=joker_core_dir.
    """
    joker_core_dir = os.path.abspath(joker_core_dir)
    cli = os.path.join(joker_core_dir, "cli.js")

    if not os.path.isfile(cli):
        die(f"FAIL_CLOSED: missing Joker-C2 cli.js at {cli}")
    if not os.path.isdir(joker_core_dir):
        die(f"FAIL_CLOSED: missing Joker-C2 core dir at {joker_core_dir}")
    if not os.path.isfile(request_json_path):
        die(f"FAIL_CLOSED: missing Joker-C2 request JSON at {request_json_path}")

    joker_out_dir = os.path.abspath(joker_out_dir)
    os.makedirs(joker_out_dir, exist_ok=True)

    out = _run(
        ["node", cli, request_json_path, "--out", joker_out_dir],
        cwd=joker_core_dir
    )

    parts = out.split()
    if len(parts) < 2:
        die("FAIL_CLOSED: unexpected Joker-C2 output: " + out)

    status = parts[0].strip()
    if status not in ("PASS", "DENY"):
        die("FAIL_CLOSED: unexpected Joker-C2 status: " + status)

    entry_hash = None
    for p in parts[1:]:
        if p.startswith("entry_hash="):
            entry_hash = p.split("=", 1)[1].strip()
            break

    if not entry_hash:
        die("FAIL_CLOSED: missing entry_hash in Joker-C2 output: " + out)

    if len(entry_hash) != 64:
        die("FAIL_CLOSED: invalid entry_hash length: " + entry_hash)

    return status, entry_hash


def _next_act_id(index_path: str) -> int:
    """
    index.md is append-only. We store lines containing:
      - act_id: <n>
    If missing, start at 1.
    """
    if not os.path.isfile(index_path):
        return 1

    txt = read_text(index_path)
    last = 0
    for line in txt.splitlines():
        line = line.strip()
        if line.startswith("- act_id:"):
            try:
                n = int(line.split(":", 1)[1].strip())
                if n > last:
                    last = n
            except Exception:
                pass
    return last + 1


def _last_entry_from_index(index_path: str) -> str:
    """
    Reads the last entry_sha256 from index.md (append-only).
    If missing, returns GENESIS.
    """
    if not os.path.isfile(index_path):
        return "GENESIS"
    txt = read_text(index_path)
    for line in reversed(txt.splitlines()):
        line = line.strip()
        if line.startswith("- entry_sha256:"):
            return line.split(":", 1)[1].strip()
    return "GENESIS"


def main():
    import argparse

    ap = argparse.ArgumentParser(
        description="GitJoker-C2 — mk_act: Joker-C2 gated, append-only, signed act builder (PASS/DENY opposable)."
    )

    ap.add_argument("--kind", default="GIT_PUBLISH", help="Act kind (e.g., GIT_PUBLISH, RELEASE, REGISTRY_ISSUE).")
    ap.add_argument("--repo", default="gitjoker-c2", help="Logical repo identifier.")
    ap.add_argument("--ref", default=None, help="Git ref (commit sha/tag) or any public reference string.")
    ap.add_argument("--note", default="", help="Human note (hashed; keep non-sensitive).")
    ap.add_argument("--ts", default=None)

    ap.add_argument("--ipr-ai", default="IPR-AI-0001")
    ap.add_argument("--ipr-operator", default="IPR-3")
    ap.add_argument("--policy-pack-id", default="UE-ΦΩ-001")

    ap.add_argument("--privkey", default="/home/manuelcoletta1/joker-c2.key")
    ap.add_argument("--key-id", default="GITJOKER-C2-ACT-001")
    ap.add_argument("--pub-ref", default="keys/joker-c2.pub.json")

    # Joker-C2 integration
    ap.add_argument("--joker-core-dir", default=os.environ.get("JOKER_C2_CORE_DIR", "/home/manuelcoletta1/hbce-joker-c2-core"))
    ap.add_argument("--joker-out-dir", default=os.environ.get("JOKER_C2_OUT_DIR", "/home/manuelcoletta1/hbce-joker-c2-core/out"))
    ap.add_argument("--joker-request", required=True, help="Path to Joker-C2 request JSON (sample allow/deny or real request).")

    args = ap.parse_args()

    ts = args.ts or now_iso_local()

    # --- Joker-C2 gate (FAIL-CLOSED always) ---
    status, joker_entry_hash = _joker_gate(args.joker_core_dir, args.joker_out_dir, args.joker_request)

    # --- Append-only ACT registry ---
    acts_dir = os.path.join(REPO_ROOT, "registry", "acts")
    index_path = os.path.join(acts_dir, "index.md")

    # ensure base structure exists (fail-closed, deterministic)
    os.makedirs(acts_dir, exist_ok=True)
    if not os.path.isfile(index_path):
        append_text(index_path, "# GitJoker-C2 ACTS (append-only)\n\n")

    act_id = _next_act_id(index_path)
    act_file = f"ACT-{zero_pad(act_id)}.json"
    act_path_rel = f"registry/acts/{act_file}"
    act_path_abs = os.path.join(REPO_ROOT, act_path_rel)

    prev_entry = _last_entry_from_index(index_path)

    payload = {
        "kind": args.kind,
        "repo": args.repo,
        "ref": args.ref,
        "note": args.note,
        "ts": ts,
        "ipr_ai": args.ipr_ai,
        "ipr_operator": args.ipr_operator,
        "policy_pack_id": args.policy_pack_id,
        "joker": {
            "status": status,
            "entry_hash": joker_entry_hash,
            "request_path": os.path.basename(args.joker_request),
        },
        "prev": prev_entry,
    }

    payload_canon = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    payload_sha = sha256_hex_utf8(payload_canon)

    # entry hash binds prev + payload_sha
    base = "|".join([prev_entry, payload_sha])
    entry = hashlib.sha256(base.encode("utf-8")).hexdigest()

    sig_b64 = openssl_sign_ed25519(args.privkey, entry)

    act = {
        "spec": "GITJOKER-ACT-0001",
        "act_id": act_id,
        "ts": ts,

        "ipr_ai": args.ipr_ai,
        "ipr_operator": args.ipr_operator,

        "policy": {
            "policy_pack_id": args.policy_pack_id,
            "mode": "FAIL_CLOSED",
            "notes": ["GDPR_MIN", "HASH_ONLY", "APPEND_ONLY"]
        },

        "joker_c2": {
            "status": status,
            "entry_hash": joker_entry_hash,
            "request_sha256": sha256_hex_utf8(read_text(args.joker_request)),
            "core_dir": os.path.abspath(args.joker_core_dir),
            "out_dir": os.path.abspath(args.joker_out_dir)
        },

        "payload": {
            "canonical": payload,
            "sha256": payload_sha
        },

        "chain": {
            "prev": prev_entry,
            "entry": entry,
            "algo": "sha256(prev|payload_sha256)"
        },

        "sign": {
            "alg": "ED25519",
            "key_id": args.key_id,
            "pub_ref": args.pub_ref,
            "sig": sig_b64
        }
    }

    write_json(act_path_abs, act)

    append_text(
        index_path,
        f"- act_id: {act_id}\n"
        f"  ts: {ts}\n"
        f"  status: {status}\n"
        f"  joker_entry_hash: {joker_entry_hash}\n"
        f"  path: {act_path_rel}\n"
        f"  entry_sha256: {entry}\n"
    )

    print(json.dumps({
        "ok": True,
        "act_id": act_id,
        "status": status,
        "entry_sha256": entry,
        "joker_entry_hash": joker_entry_hash,
        "path": act_path_rel
    }, indent=2))


if __name__ == "__main__":
    main()
