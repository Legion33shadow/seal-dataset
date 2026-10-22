#!/usr/bin/env python3
"""seal-dataset: seal a dataset snapshot in LEGION SEAL. Hash only, Python standard library only.

  seal_dataset.py seal DIR [--name NAME] [--revision REV | --git] [--mask-names] [--no-label] [--out-dir D] [--test]
  seal_dataset.py manifest DIR [--salt-file F] [--out M]          offline: recompute the manifest of a folder
  seal_dataset.py check DIR RECEIPT [--salt-file F]               offline: recompute the manifest, then verify_seal.py

The manifest is verify_seal.dataset_manifest, the function of the bundled verifier (generated from legion-core): one line
per regular file, "<sha256> <size> <relative path>", sorted by the UTF-8 bytes of the path; .git ignored, symlinks and
non-NFC paths refused. --mask-names replaces each path with HMAC-SHA256(salt, path) under a random local salt.
Only SHA-256(manifest) and an optional label "dataset <name>@<rev>" are sent: never a file, a file hash or a file name."""
import argparse, glob, hashlib, hmac, json, os, re, subprocess, sys, time, unicodedata, urllib.error, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from verify_seal import Invalid, dataset_manifest, file_sha  # noqa: E402  (same code as the verifier: one manifest definition)

BASE = os.environ.get("SEAL_BASE", "https://seal.legion-api.com")
LFS = b"version https://git-lfs.github.com/spec/v1"
CLAIM = ("This seal proves that this snapshot (these file hashes) existed at this date (registry clock). It does NOT prove "
         "the dataset's quality, licence, ownership or origin. Single operator, no independent witness yet.")
FORMATS = {False: "legion-dataset-manifest/v0: <sha256> <size> <path>, sorted by path bytes",
           True: "legion-dataset-manifest-masked/v0: <sha256> <size> <HMAC-SHA256(salt, path) hex>, sorted by that hex"}


def mask(manifest, salt_hex):
    key = bytes.fromhex(salt_hex)
    rows = []
    for line in manifest.decode("utf-8").splitlines():
        sha, size, path = line.split(" ", 2)
        rows.append("%s %s %s\n" % (sha, size, hmac.new(key, path.encode("utf-8"), hashlib.sha256).hexdigest()))
    return "".join(sorted(rows, key=lambda r: r.split(" ", 2)[2])).encode("utf-8")


def build(d, salt_hex=None):
    """(manifest bytes, file_count, total_bytes, lfs_pointer_files) of folder d, masked if salt_hex."""
    m = dataset_manifest(d)
    rows = [l.split(" ", 2) for l in m.decode("utf-8").splitlines()]
    lfs = 0
    for sha, size, path in rows:
        if int(size) < 1024:
            with open(os.path.join(d, path), "rb") as f:
                lfs += f.read(len(LFS)) == LFS
    return (mask(m, salt_hex) if salt_hex else m), len(rows), sum(int(r[1]) for r in rows), lfs


def read_salt(path):
    s = open(path).read().strip()
    if not re.fullmatch(r"[0-9a-f]{32,64}", s):
        raise Invalid("salt file: 32 to 64 lowercase hex expected")
    return s


def git_rev(d):
    run = lambda *a: subprocess.run(["git", "-C", d] + list(a), capture_output=True, text=True, check=True).stdout.strip()  # noqa: E731
    if run("status", "--porcelain"):
        raise Invalid("git working tree is not clean: the folder does not match a revision (commit, or drop --git)")
    return run("rev-parse", "HEAD")


def label_for(name, rev):
    """Registry rules: <=64 chars, NFC, no URL, no control character. The name is cut, never the revision."""
    tail = "@" + rev[:7] if re.fullmatch(r"[0-9a-f]{40}", rev or "") else "@" + (rev or "local")[:16]
    name = "".join(c for c in unicodedata.normalize("NFC", name) if unicodedata.category(c)[0] != "C")
    if "://" in name.lower() or "www." in name.lower():
        name = "dataset"
    return ("dataset " + name[:max(64 - 8 - len(tail), 0)] + tail).strip()


def submit(base, body, test, tries=3):
    hdr = {"Content-Type": "application/json", "User-Agent": "seal-dataset/0"}
    if test:
        hdr["X-Legion-Test"] = "seal-dataset"
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    for k in range(tries):
        q = urllib.request.Request(base + "/seal/v1/submit", data=data, headers=hdr, method="POST")
        try:
            with urllib.request.urlopen(q, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            msg = e.read().decode("utf-8", "replace")[:300]
            if e.code == 429 and k + 1 < tries:
                time.sleep(min(int(e.headers.get("Retry-After") or 60), 60)); continue
            raise RuntimeError("HTTP %d: %s" % (e.code, msg))


def verify(receipt, sha, vkey=None):
    """Runs the bundled verify_seal.py unchanged. (True|False|None, last line); None = cryptography missing."""
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return None, "skipped: python3 'cryptography' not installed (pip install cryptography)"
    cmd = [sys.executable, "-I", os.path.join(HERE, "verify_seal.py"), receipt, "--sha256", sha] + (["--log-vkey", vkey] if vkey else [])
    p = subprocess.run(cmd, capture_output=True, text=True)
    last = (p.stdout.strip().splitlines() or [""])[-1]
    return p.returncode == 0 and last.startswith("RESULTAT: VALIDE"), last


def snippet(r, man_name, n, total, masked, rdir_name):
    pub = r["proof_url"].split("/seal/v1/")[0]; i = r["leaf_index"]
    rec = os.path.basename(rdir_name)
    salt = " --salt-file manifest.salt" if masked else ""
    return "\n".join([
        "[![sealed](%s/seal/v1/badge/%d.svg)](%s)" % (pub, i, r["proof_url"]), "",
        "**Snapshot seal.** Manifest SHA-256 `%s` (%d files, %d bytes%s), LEGION SEAL leaf [%d](%s), recorded %s (registry clock)."
        % (r["entry"]["sha256"], n, total, ", file names masked" if masked else "", i, r["proof_url"], r["observed_at"]), "",
        "> " + CLAIM, "",
        "Verify offline (Python 3 + `cryptography`, no network), from a copy of this dataset:", "",
        "```",
        "curl -sO https://raw.githubusercontent.com/Legion33shadow/legion-seal/main/verify_seal.py",
        "python3 seal_dataset.py manifest .%s --out %s" % (salt, man_name),
        "python3 verify_seal.py %s --file %s     # RESULTAT: VALIDE" % (rec, man_name),
        "```", ""])


def cmd_seal(a):
    d = os.path.abspath(a.dir)
    rev = git_rev(d) if a.git else (a.revision or "local")
    name = a.name or os.environ.get("SEAL_DATASET_NAME") or os.path.basename(d.rstrip("/"))
    os.makedirs(a.out_dir, exist_ok=True)
    salt = None
    if a.mask_names:
        sp = os.path.join(a.out_dir, "manifest.salt")
        if os.path.exists(sp):
            salt = read_salt(sp)
        else:
            salt = os.urandom(16).hex()
            fd = os.open(sp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600); os.write(fd, (salt + "\n").encode()); os.close(fd)
    m, n, total, lfs = build(d, salt)
    sha = hashlib.sha256(m).hexdigest()
    mp = os.path.join(a.out_dir, "manifest.masked.txt" if salt else "manifest.txt")
    with open(mp, "wb") as f:
        f.write(m)
    print("seal-dataset: %s %d files %d bytes manifest %s sha256=%s" % (d, n, total, mp, sha))
    if lfs:
        print("seal-dataset: WARNING %d Git LFS pointer files: the manifest hashes the pointers, not the content (run git lfs pull)" % lfs)
    body = {"sha256": sha}
    if not a.no_label:
        body["label"] = label_for(name, rev)
    print("seal-dataset: POST %s/seal/v1/submit %s%s" % (a.base.rstrip("/"), json.dumps(body, ensure_ascii=False), " (X-Legion-Test)" if a.test else ""))
    r = submit(a.base.rstrip("/"), body, a.test)
    if r.get("entry", {}).get("sha256") != sha:
        raise Invalid("receipt hash does not match the local manifest hash")
    i = r["leaf_index"]
    r["seal_dataset_local"] = {"format": FORMATS[bool(salt)], "manifest_file": os.path.basename(mp), "manifest_sha256": sha,
                               "dataset": name, "revision": rev, "file_count": n, "total_bytes": total, "lfs_pointer_files": lfs,
                               "salt_file": "manifest.salt" if salt else None, "claim": CLAIM}
    rp = os.path.join(a.out_dir, "dataset.seal-%d.json" % i)
    with open(rp, "w") as f:
        json.dump(r, f, ensure_ascii=False, indent=1)
    ok, vmsg = verify(rp, sha, a.log_vkey)
    sn = snippet(r, os.path.basename(mp), n, total, bool(salt), rp)
    with open(os.path.join(a.out_dir, "DATASET_CARD_SNIPPET.md"), "w") as f:
        f.write(sn)
    print("seal-dataset: leaf %d%s proof %s receipt %s verify: %s" % (i, " (already sealed: first entry)" if r.get("duplicate_of_first_submission") else "",
                                                                    r["proof_url"], rp, vmsg))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write("## LEGION SEAL — dataset snapshot\n\n" + sn + "\n")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            f.write("leaf=%d\nreceipt=%s\nmanifest=%s\nmanifest-sha256=%s\nbadge=%s\n" % (i, rp, mp, sha, sn.splitlines()[0]))
    return 1 if ok is False else 0


def cmd_manifest(a):
    m, n, total, lfs = build(a.dir, read_salt(a.salt_file) if a.salt_file else None)
    if a.out:
        with open(a.out, "wb") as f:
            f.write(m)
    else:
        sys.stdout.buffer.write(m)
    print("%d files %d bytes sha256=%s%s" % (n, total, hashlib.sha256(m).hexdigest(), " (%d LFS pointers)" % lfs if lfs else ""), file=sys.stderr)
    return 0


def cmd_check(a):
    m = build(a.dir, read_salt(a.salt_file) if a.salt_file else None)[0]
    sha = hashlib.sha256(m).hexdigest()
    print("manifest sha256 %s (recomputed from %s)" % (sha, a.dir))
    ok, msg = verify(a.receipt, sha, a.log_vkey)
    print(msg)
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0]); sp = ap.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("seal"); s.add_argument("dir"); s.add_argument("--name"); g = s.add_mutually_exclusive_group()
    g.add_argument("--revision"); g.add_argument("--git", action="store_true")
    s.add_argument("--mask-names", action="store_true"); s.add_argument("--no-label", action="store_true")
    s.add_argument("--out-dir", default="seal-dataset"); s.add_argument("--base", default=BASE)
    s.add_argument("--test", action="store_true", help="send X-Legion-Test: real seal, excluded from the registry's counters and feed")
    m = sp.add_parser("manifest"); m.add_argument("dir"); m.add_argument("--salt-file"); m.add_argument("--out")
    c = sp.add_parser("check"); c.add_argument("dir"); c.add_argument("receipt"); c.add_argument("--salt-file")
    for p in (s, c):
        p.add_argument("--log-vkey", help="registry key (default: the key pinned in verify_seal.py)")
    a = ap.parse_args(argv)
    try:
        return {"seal": cmd_seal, "manifest": cmd_manifest, "check": cmd_check}[a.cmd](a)
    except (Invalid, RuntimeError, OSError, subprocess.CalledProcessError, urllib.error.URLError) as ex:
        print("seal-dataset: ERROR %s" % ex, file=sys.stderr); return 1


if __name__ == "__main__":
    sys.exit(main())
