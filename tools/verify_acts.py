#!/usr/bin/env python3
"""
GitJoker-C2 — verify_acts
Deterministic verifier for append-only ACT chains.

Modes:
- STRICT (default): single chain, no resets (prev must match previous entry).
- --allow-genesis-resets: allow multiple segments starting from GENESIS.
  This is useful during bootstrap/migration, but STRICT is the canonical goal.

Checks:
- index.md ↔ ACT-*.json consistency
- payload canonicalization -> payload_sha256
- chain entry = sha256(prev|payload_sha256)
- (optional) ED25519 signature verify via OpenSSL, if pubkey PEM is available

Fail-closed: any mismatch => FAIL and non-zero exit.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

INDEX_DEFAULT = os.path.join(REPO_ROOT, "registry", "acts", "index.md")
ACTS_DIR_DEFAULT = os.path.join(REPO_ROOT, "registry", "acts")


def die(msg: str, code: int = 1) -> None:
    sys.stderr.write(str(msg).rstrip() + "\n")
    raise SystemExit(code)


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def sha256_hex_utf8(s: str) -> str:
    b = s.replace("\r\n", "\n").encode("utf-8")
    return hashlib.sha256(b).hexdigest()


def canonical_payload_string(payload_obj: Dict[str, Any]) -> str:
    # Must match mk_act.py canonicalization:
    # json.dumps(..., indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    s = json.dumps(payload_obj, indent=2, sort_keys=True, ensure_ascii=False)
    return s.replace("\r\n", "\n") + "\n"


def compute_entry(prev: str, payload_sha256: str) -> str:
    base = "|".join([prev, payload_sha256])
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def parse_index(index_md: str) -> List[Dict[str, Any]]:
    """
    Parses blocks like:
      - act_id: 3
        ts: ...
        status: PASS
        joker_entry_hash: ...
        path: registry/acts/ACT-000003.json
        entry_sha256: <hex>
    """
    lines = index_md.splitlines()
    entries: List[Dict[str, Any]] = []

    cur: Optional[Dict[str, Any]] = None
    for raw in lines:
        line = raw.rstrip("\n")
        if line.strip().startswith("- act_id:"):
            if cur:
                entries.append(cur)
            cur = {"act_id": int(line.split(":", 1)[1].strip())}
            continue

        if not cur:
            continue

        m = re.match(r"^\s+([a-zA-Z0-9_]+):\s*(.*)\s*$", line)
        if m:
            k = m.group(1)
            v = m.group(2)
            cur[k] = v

    if cur:
        entries.append(cur)

    if not entries:
        die("FAIL: index.md has no act entries (append-only blocks not found).")

    # Ensure monotonic act_id
    last = 0
    for e in entries:
        if e["act_id"] <= last:
            die("FAIL: index.md act_id is not strictly increasing.")
        last = e["act_id"]

    return entries


def find_pub_pem(pub_ref_path: str) -> str:
    p = os.path.join(REPO_ROOT, pub_ref_path)
    if not os.path.isfile(p):
        die(f"FAIL: pub_ref not found: {pub_ref_path} (resolved: {p})")

    obj = read_json(p)
    if not isinstance(obj, dict):
        die(f"FAIL: pub_ref JSON is not an object: {pub_ref_path}")

    candidates = [
        obj.get("public_key_pem"),
        obj.get("publicKeyPem"),
        obj.get("pem"),
        obj.get("public_key"),
        obj.get("publicKey"),
    ]
    for c in candidates:
        if isinstance(c, str) and "BEGIN PUBLIC KEY" in c:
            return c

    die(f"FAIL: could not find a PEM public key in pub_ref JSON: {pub_ref_path}")


def openssl_verify_ed25519(pub_pem: str, message_ascii: str, sig_b64: str) -> None:
    tmp_dir = os.path.join(REPO_ROOT, ".tmp_verify")
    os.makedirs(tmp_dir, exist_ok=True)

    pub_path = os.path.join(tmp_dir, "pub.pem")
    msg_path = os.path.join(tmp_dir, "msg.txt")
    sig_path = os.path.join(tmp_dir, "sig.bin")

    with open(pub_path, "w", encoding="utf-8") as f:
        f.write(pub_pem.strip() + "\n")

    with open(msg_path, "wb") as f:
        f.write(message_ascii.encode("ascii"))

    try:
        sig_bin = base64.b64decode(sig_b64)
    except Exception:
        die("FAIL: signature is not valid base64")

    with open(sig_path, "wb") as f:
        f.write(sig_bin)

    cmd = [
        "openssl", "pkeyutl", "-verify",
        "-pubin",
        "-inkey", pub_path,
        "-rawin",
        "-in", msg_path,
        "-sigfile", sig_path,
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        die("FAIL: signature verify failed:\n" + (r.stderr or r.stdout).strip())


def load_act(act_abs_path: str) -> Dict[str, Any]:
    if not os.path.isfile(act_abs_path):
        die(f"FAIL: missing ACT file: {act_abs_path}")
    obj = read_json(act_abs_path)
    if not isinstance(obj, dict):
        die(f"FAIL: ACT JSON is not an object: {act_abs_path}")
    return obj


def main() -> None:
    ap = argparse.ArgumentParser(description="GitJoker-C2 — deterministic verifier for ACT chain(s).")
    ap.add_argument("--index", default=INDEX_DEFAULT, help="Path to registry/acts/index.md")
    ap.add_argument("--acts-dir", default=ACTS_DIR_DEFAULT, help="Directory containing ACT-*.json files")
    ap.add_argument("--from", dest="from_id", type=int, default=None, help="Start act_id (inclusive)")
    ap.add_argument("--to", dest="to_id", type=int, default=None, help="End act_id (inclusive)")
    ap.add_argument("--skip-sig", action="store_true", help="Skip ED25519 signature verification (NOT recommended).")
    ap.add_argument("--allow-genesis-resets", action="store_true",
                    help="Allow multiple segments starting from GENESIS (bootstrap mode).")
    ap.add_argument("--json", action="store_true", help="Emit JSON report on success.")
    args = ap.parse_args()

    index_path = os.path.abspath(args.index)
    acts_dir = os.path.abspath(args.acts_dir)

    if not os.path.isfile(index_path):
        die(f"FAIL: index.md not found: {index_path}")
    if not os.path.isdir(acts_dir):
        die(f"FAIL: acts dir not found: {acts_dir}")

    entries = parse_index(read_text(index_path))

    if args.from_id is not None:
        entries = [e for e in entries if e["act_id"] >= args.from_id]
    if args.to_id is not None:
        entries = [e for e in entries if e["act_id"] <= args.to_id]
    if not entries:
        die("FAIL: no entries in selected range.")

    report: List[Dict[str, Any]] = []
    expected_prev = "GENESIS"
    segments = 1

    for idx in entries:
        act_id = idx["act_id"]
        path_rel = idx.get("path")
        entry_sha_from_index = idx.get("entry_sha256")

        if not path_rel or not isinstance(path_rel, str):
            die(f"FAIL: index entry act_id={act_id} missing path")
        if not entry_sha_from_index or not isinstance(entry_sha_from_index, str):
            die(f"FAIL: index entry act_id={act_id} missing entry_sha256")

        act_abs = os.path.join(REPO_ROOT, path_rel)
        act = load_act(act_abs)

        if act.get("spec") != "GITJOKER-ACT-0001":
            die(f"FAIL: act_id={act_id} invalid spec")
        if int(act.get("act_id")) != int(act_id):
            die(f"FAIL: act_id mismatch (index={act_id} file={act.get('act_id')})")

        chain = act.get("chain") or {}
        chain_prev = chain.get("prev")
        chain_entry = chain.get("entry")

        if not isinstance(chain_prev, str) or not isinstance(chain_entry, str):
            die(f"FAIL: act_id={act_id} missing chain.prev/chain.entry")

        # STRICT single-chain expectation
        if chain_prev != expected_prev:
            if args.allow_genesis_resets and chain_prev == "GENESIS":
                # Start a new segment
                segments += 1
                expected_prev = "GENESIS"
            else:
                die(
                    f"FAIL: act_id={act_id} chain.prev mismatch\n"
                    f"expected={expected_prev}\n"
                    f"found={chain_prev}"
                )

        # Recompute payload sha256
        payload = act.get("payload") or {}
        payload_canon_obj = payload.get("canonical")
        payload_sha_file = payload.get("sha256")

        if not isinstance(payload_canon_obj, dict):
            die(f"FAIL: act_id={act_id} payload.canonical is not an object")

        payload_canon_str = canonical_payload_string(payload_canon_obj)
        payload_sha_calc = sha256_hex_utf8(payload_canon_str)

        if payload_sha_file != payload_sha_calc:
            die(
                f"FAIL: act_id={act_id} payload.sha256 mismatch\n"
                f"file={payload_sha_file}\n"
                f"calc={payload_sha_calc}"
            )

        # Recompute entry hash
        entry_calc = compute_entry(chain_prev, payload_sha_calc)
        if chain_entry != entry_calc:
            die(
                f"FAIL: act_id={act_id} chain.entry mismatch\n"
                f"file={chain_entry}\n"
                f"calc={entry_calc}"
            )

        if entry_sha_from_index != chain_entry:
            die(
                f"FAIL: act_id={act_id} index entry_sha256 mismatch\n"
                f"index={entry_sha_from_index}\n"
                f"act={chain_entry}"
            )

        # Signature verify (optional)
        if not args.skip_sig:
            sign = act.get("sign") or {}
            sig_b64 = sign.get("sig")
            pub_ref = sign.get("pub_ref")
            alg = sign.get("alg")

            if alg != "ED25519":
                die(f"FAIL: act_id={act_id} sign.alg expected ED25519, got {alg}")
            if not isinstance(sig_b64, str) or not sig_b64.strip():
                die(f"FAIL: act_id={act_id} missing sign.sig")
            if not isinstance(pub_ref, str) or not pub_ref.strip():
                die(f"FAIL: act_id={act_id} missing sign.pub_ref")

            pub_pem = find_pub_pem(pub_ref)
            openssl_verify_ed25519(pub_pem, chain_entry, sig_b64)

        joker = act.get("joker_c2") or {}
        report.append({
            "act_id": act_id,
            "path": path_rel,
            "status": joker.get("status"),
            "prev": chain_prev,
            "entry": chain_entry,
            "payload_sha256": payload_sha_calc,
            "sig_verified": (not args.skip_sig),
        })

        expected_prev = chain_entry

    if args.json:
        print(json.dumps({"ok": True, "segments": segments, "verified": report}, indent=2))
    else:
        print(f"PASS_ACTS verified={len(report)} segments={segments} last_entry={expected_prev}")


if __name__ == "__main__":
    main()
