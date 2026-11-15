#!/usr/bin/env python3
"""Safe publication of current, validated PatchGuard working directory.

Runs on the student's own WSL machine (where the current sources, generated
reports and GitHub credentials exist). Clones the remote, overlays the bounded
submission set without deleting existing content, commits and fast-forward
pushes. Never uses force push and never publishes local .git or credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

DEFAULT_REMOTE = "https://github.com/pooryaamirniya/DNS_Project_G11.git"
DIRS = ("patchguard", "configs", "targets", "tests", "tools", "docs", ".github")
FILES = (
    "README.md", "README_FA.md", "Dockerfile", ".dockerignore",
    "LICENSE", "LICENSE.md", "LICENSE.txt", "requirements.txt",
    "pyproject.toml", "Makefile", "pytest.ini", "setup.cfg", ".gitattributes",
)
REQUIRED_FILES = (
    "patchguard/cli.py", "patchguard/detection.py",
    "tools/docker_run.sh", "tools/blind_patch_test.py", "tools/evaluate_candidate.py",
    "tools/quality_gate.py", "tools/assert_matrix.py",
    ".github/workflows/patchguard.yml", ".github/workflows/quality-gate.yml",
    "targets/cjsonreal/source_manifest.json", "targets/cjsonreal/upstream/v1.7.17/cJSON.c",
    "targets/cjsonreal/upstream/v1.7.18/cJSON.c",
    "artifacts/ci/report.json", "artifacts/blind-patches/manifest.json",
    "artifacts/blind-patches/summary.json", "artifacts/quality-gate/quality_report.json",
)
IGNORE_DIRS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "venv", "node_modules", ".idea", ".vscode", "build", "obj", "bin", ".tox"}
IGNORE_SUFFIXES = {".pyc", ".pyo", ".bak", ".swp", ".swo", ".tmp", ".o", ".so", ".a", ".exe", ".dll", ".dmp", ".log"}
IGNORE_NAMES = {".env", ".env.local", "id_rsa", "id_ed25519", "credentials.json", "token.txt", ".DS_Store", "core"}
IGNORE_PATTERNS = """# PatchGuard generated build outputs / transient files
__pycache__/
*.py[cod]
.pytest_cache/
.mypy_cache/
.ruff_cache/
.venv/
venv/
.idea/
.vscode/
*.bak
*.swp
*.tmp
*.o
*.so
*.a
*.core
core
.env
.env.*
*.pem
*.key
artifacts/**/build/
"""
MAX_SINGLE_FILE = 35 * 1024 * 1024
EXPECTED = {
    "frame-correct": 0, "frame-incomplete": 10, "frame-regression": 20,
    "cjsonreal-correct": 0, "cjsonreal-incomplete": 10,
    "cjsonreal-regression": 20,
}


def fail(message: str):
    raise RuntimeError(message)


def run(args, *, cwd=None, env=None, capture=True, check=True):
    proc = subprocess.run(args, cwd=cwd, env=env, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None,
                          check=False)
    if check and proc.returncode:
        output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        fail(f"Command failed ({proc.returncode}): {' '.join(map(str, args))}\n{output[-3000:]}")
    return proc


def json_at(root, rel):
    path = root / rel
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        fail(f"Missing/invalid evidence {rel}: {e}")


def preflight(root, skip_gate=False):
    for file in REQUIRED_FILES:
        if not (root / file).is_file():
            fail(f"Required submission file is missing: {file}")
    report = json_at(root, "artifacts/ci/report.json")
    actual = {item.get("scenario"): item.get("exit_code") for item in report.get("scenarios", [])}
    if actual != EXPECTED:
        fail(f"6-case matrix does not match expected outcomes: {actual}")
    summary = json_at(root, "artifacts/blind-patches/summary.json")
    if summary.get("passed") != 9 or summary.get("total") != 9:
        fail(f"Blind matrix not 9/9 in saved report: {summary.get('passed')}/{summary.get('total')}")
    if not skip_gate:
        env = dict(os.environ, PYTHONPATH=str(root) + (os.pathsep + os.environ["PYTHONPATH"] if "PYTHONPATH" in os.environ else ""))
        run([sys.executable, str(root / "tools/quality_gate.py"), "--strict"], cwd="/tmp", env=env)
        gate = json_at(root, "artifacts/quality-gate/quality_report.json")
        if gate.get("status") != "PASS" or gate.get("errors") or gate.get("warnings"):
            fail("Quality Gate must be PASS with no errors or warnings")
    print("Preflight: official 6/6, blind 9/9, quality gate PASS", flush=True)


def safe_file(path: Path, src_root: Path) -> bool:
    relative = path.relative_to(src_root)
    if any(p in IGNORE_DIRS for p in relative.parts[:-1]):
        return False
    name = path.name
    if name in IGNORE_NAMES or name.endswith(tuple(IGNORE_SUFFIXES)):
        return False
    if name.startswith(".env.") or name.endswith((".pem", ".key", ".p12", ".pfx")):
        return False
    if path.is_symlink():
        fail(f"Symbolic link needs manual inspection: {relative}")
    if not path.is_file():
        return False
    if path.stat().st_size > MAX_SINGLE_FILE:
        fail(f"File exceeds 35 MiB, review before uploading: {relative}")
    with path.open("rb") as f:
        if f.read(4) == b"\x7fELF":
            return False  # Rebuilt in CI; never commit generated ELF files.
    return True


def candidates(src):
    for folder in DIRS:
        origin = src / folder
        if origin.is_dir():
            yield from (f for f in origin.rglob("*") if safe_file(f, src))
    for name in FILES:
        file = src / name
        if file.is_file() and safe_file(file, src):
            yield file
    # Evidence: reports, manifests, minimized inputs and reproducers; no build outputs.
    evidence = src / "artifacts"
    if evidence.is_dir():
        for group in ("ci", "blind-patches", "quality-gate"):
            origin = evidence / group
            if origin.is_dir():
                yield from (f for f in origin.rglob("*") if safe_file(f, src))


def overlay(src, dst):
    files = {}
    for file in candidates(src):
        files[file.relative_to(src).as_posix()] = file
    if len(files) < 35:
        fail(f"Only {len(files)} project files were selected; investigate before committing")
    skipped = []
    for relative, file in sorted(files.items()):
        dest_rel = relative
        dest = dst / relative
        # Preserve unrelated remote README if repo already hosts other content.
        if relative == "README.md" and dest.is_file():
            old = dest.read_text(encoding="utf-8", errors="replace")
            if "PatchGuard" not in old and dest.read_bytes() != file.read_bytes():
                dest_rel = "PATCHGUARD_README.md"
                dest = dst / dest_rel
                print("Remote README preserved; project README -> PATCHGUARD_README.md")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and dest.is_dir():
            fail(f"Existing remote directory conflicts with file: {dest_rel}")
        shutil.copy2(file, dest)
    gitignore = dst / ".gitignore"
    previous = gitignore.read_text(encoding="utf-8") if gitignore.is_file() else ""
    # Add only missing exact lines; retain the remote's pre-existing ignore list.
    new_lines = [line for line in IGNORE_PATTERNS.splitlines() if line and line not in previous.splitlines()]
    if new_lines:
        gitignore.write_text(previous.rstrip() + ("\n\n" if previous.strip() else "") + "\n".join(new_lines) + "\n", encoding="utf-8")
    return len(files)


def main():
    p = argparse.ArgumentParser(description="Publish the validated PatchGuard project to GitHub safely")
    p.add_argument("--repo-url", default=DEFAULT_REMOTE,
                   help="Remote repository (default: user-provided DNS_Project_G11 URL)")
    p.add_argument("--dry-run", action="store_true", help="Prepare and inspect commit, but do not push")
    p.add_argument("--skip-gate", action="store_true", help="Skip rerunning gate; still verify last report (not recommended)")
    p.add_argument("--branch", default=None, help="Optional new publication branch; default is remote default branch")
    args = p.parse_args()
    root = Path(__file__).resolve().parent.parent
    if not shutil.which("git"):
        fail("git executable missing: sudo apt-get install git")
    preflight(root, skip_gate=args.skip_gate)
    with tempfile.TemporaryDirectory(prefix="patchguard-github-") as temp:
        repo = Path(temp) / "DNS_Project_G11"
        print("Cloning remote; GitHub authentication may be requested...", flush=True)
        proc = subprocess.run(["git", "clone", args.repo_url, str(repo)])
        if proc.returncode:
            fail("Cannot clone remote. Check URL/access and authenticate via gh auth login or SSH.")
        if args.branch:
            run(["git", "switch", "-c", args.branch], cwd=repo)
        else:
            head = run(["git", "symbolic-ref", "--short", "HEAD"], cwd=repo).stdout.strip()
            # An empty GitHub repository can default to master in old Git configs.
            has_commit = run(["git", "rev-parse", "--verify", "HEAD"], cwd=repo, check=False).returncode == 0
            if not has_commit and head != "main":
                run(["git", "symbolic-ref", "HEAD", "refs/heads/main"], cwd=repo)
        count = overlay(root, repo)
        run(["git", "add", "-A"], cwd=repo)
        status = run(["git", "status", "--short"], cwd=repo).stdout
        print(f"Selected {count} source/evidence files. Git status:\n{status[:11000]}", flush=True)
        staged = run(["git", "diff", "--cached", "--name-only"], cwd=repo).stdout.strip().splitlines()
        if not staged:
            print("No changes; repository already matches the submitted project.")
            return 0
        # Abort rather than accidentally staging a pre-existing auth credential.
        for name in staged:
            if name.startswith(".git/") or name.endswith((".pem", ".key")) or Path(name).name in IGNORE_NAMES:
                fail(f"Unsafe file was staged; aborting upload: {name}")
        whitespace = run(["git", "diff", "--cached", "--check"], cwd=repo, check=False)
        if whitespace.returncode:
            print("WARNING: Git reports pre-existing whitespace issues in staged files; upstream source is not auto-modified.")
        print("Staged summary:\n" + run(["git", "diff", "--cached", "--stat"], cwd=repo).stdout[-12000:], flush=True)
        if args.dry_run:
            print("Dry run complete: nothing pushed.")
            return 0
        identity = run(["git", "var", "GIT_AUTHOR_IDENT"], cwd=repo, check=False)
        if identity.returncode:
            fail("Git user identity missing. Set git config --global user.name and user.email, then rerun.")
        run(["git", "commit", "-m", "Submit validated PatchGuard security patch verification project"], cwd=repo, capture=False)
        # No force. Concurrent remote changes will cause a safe non-fast-forward error.
        run(["git", "push", "-u", "origin", "HEAD"], cwd=repo, capture=False)
        branch = run(["git", "symbolic-ref", "--short", "HEAD"], cwd=repo).stdout.strip()
        sha = run(["git", "rev-parse", "--short", "HEAD"], cwd=repo).stdout.strip()
        print(f"PUBLISHED: {args.repo_url} branch={branch} commit={sha}", flush=True)
        print("Next: open GitHub Actions -> PatchGuard Full Quality Gate; verify green status.")
        print("To inspect the upload: visit the repository URL in your browser.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError) as exc:
        print("PUBLISH ERROR:", exc, file=sys.stderr)
        sys.exit(1)
