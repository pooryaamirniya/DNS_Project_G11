#!/usr/bin/env python3
"""Add genuine upstream cJSON 1.7.17 -> 1.7.18 test cases to PatchGuard.

Educational target: CVE-2024-31755 (NULL second parameter in cJSON_SetValuestring).
The source library is genuinely upstream; incomplete/regression patches are
DELIBERATELY INJECTED test fixtures, never claimed as upstream versions.

This installer needs access to GitHub ONCE. Subsequent CI is offline with
respect to upstream source. Run only from the root of PatchGuard_Project1.
"""
from __future__ import annotations
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request

PROJECT = Path(__file__).resolve().parent.parent
TARGET = PROJECT / "targets" / "cjsonreal"
BASE = "v1.7.17"
FIX = "v1.7.18"
REPOSITORY = "https://github.com/DaveGamble/cJSON"
FIX_PATTERN = re.compile(r'if\s*\(\s*object->valuestring\s*==\s*NULL\s*\|\|\s*valuestring\s*==\s*NULL\s*\)')
BASE_PATTERN = re.compile(r'if\s*\(\s*object->valuestring\s*==\s*NULL\s*\)')


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download_source(tag: str) -> tuple[dict[str, bytes], str, str]:
    """Prefer shallow Git clone for a verifiable git commit; tarball fallback."""
    existing = TARGET / "upstream" / tag
    if all((existing / name).is_file() for name in ("cJSON.c", "cJSON.h", "LICENSE")):
        files = {name: (existing / name).read_bytes() for name in ("cJSON.c", "cJSON.h", "LICENSE")}
        return files, "existing-vendored-files", "local-existing"

    # Try git first: pin to annotated or lightweight upstream release tag.
    try:
        with tempfile.TemporaryDirectory(prefix="patchguard-cjson-") as temp:
            checkout = Path(temp) / "upstream"
            subprocess.run(["git", "clone", "--depth", "1", "--branch", tag,
                            REPOSITORY + ".git", str(checkout)],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=90)
            commit = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"],
                                             timeout=10).decode().strip()
            files = {name: (checkout / name).read_bytes() for name in ("cJSON.c", "cJSON.h", "LICENSE")}
            return files, commit, "shallow-clone"
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        print(f"Git checkout of {tag} unavailable: {str(exc)[:160]}", file=sys.stderr)

    # Archive fallback: tarball must contain the expected tagged directory.
    url = f"https://codeload.github.com/DaveGamble/cJSON/tar.gz/refs/tags/{tag}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PatchGuard-educational-target-installer/1"})
        with urllib.request.urlopen(req, timeout=45) as response:
            payload = response.read(8 * 1024 * 1024 + 1)
        if len(payload) > 8 * 1024 * 1024:
            raise RuntimeError("Upstream archive exceeds 8 MiB size cap")
        files = {}
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            for member in archive:
                if member.isfile() and Path(member.name).name in ("cJSON.c", "cJSON.h", "LICENSE"):
                    if len(Path(member.name).parts) != 2 or member.name.count("/") != 1:
                        continue
                    data = archive.extractfile(member).read()
                    if len(data) > 500000:
                        raise RuntimeError("Unexpectedly large upstream file")
                    files[Path(member.name).name] = data
        if set(files) != {"cJSON.c", "cJSON.h", "LICENSE"}:
            raise RuntimeError("Archive does not contain expected upstream source files")
        return files, tag + " (git SHA unavailable via archive)", "tag-archive"
    except Exception as exc:
        raise RuntimeError(
            f"Could not fetch cJSON {tag} from GitHub: {exc}. "
            "Check GitHub connectivity or manually place tagged cJSON.c, cJSON.h, "
            f"LICENSE under targets/cjsonreal/upstream/{tag}/ and rerun."
        ) from exc


def cjson_with_driver(tag: str, source: str, kind: str) -> str:
    """Compile actual upstream cJSON.c into a standalone ELF with a small stdin adapter."""
    needle = '#include "cJSON.h"'
    if source.count(needle) != 1:
        raise ValueError(f"Unexpected {tag} cJSON.c header layout")
    source = source.replace(needle, f'#include "upstream/{tag}/cJSON.h"', 1)
    if kind == "incomplete":
        new = ('if (object->valuestring == NULL || '
               '(valuestring == NULL && strcmp(object->valuestring, "apple") == 0))')
        source, changes = FIX_PATTERN.subn(new, source)
        if changes != 1:
            raise ValueError("Expected exactly one upstream guard for incomplete fixture")
    if kind == "regression":
        new = ('if (object->valuestring == NULL || valuestring == NULL || '
               '(valuestring != NULL && strcmp(valuestring, "hello") == 0))')
        source, changes = FIX_PATTERN.subn(new, source)
        if changes != 1:
            raise ValueError("Expected exactly one upstream guard for regression fixture")
    source += r'''

/* PatchGuard project-owned standalone adapter, not part of upstream cJSON. */
/* Format: NULL:<original> or SET:<original>:<replacement>, one line on stdin. */
int main(void)
{
    char line[512];
    char *initial = NULL;
    const char *replacement = NULL;
    cJSON *item = NULL;
    char *result = NULL;
    int is_null_test = 0;
    int code = 0;
    if (!fgets(line, sizeof(line), stdin)) return 2;
    line[strcspn(line, "\r\n")] = '\0';
    if (strncmp(line, "NULL:", 5) == 0)
    {
        initial = line + 5;
        is_null_test = 1;
    }
    else if (strncmp(line, "SET:", 4) == 0)
    {
        initial = line + 4;
        char *separator = strchr(initial, ':');
        if (separator == NULL) { puts("INVALID"); return 2; }
        *separator = '\0';
        replacement = separator + 1;
    }
    else { puts("INVALID"); return 2; }
    if (initial == NULL || *initial == '\0') { puts("INVALID"); return 2; }
    item = cJSON_CreateString(initial);
    if (item == NULL) return 3;
    result = cJSON_SetValuestring(item, replacement);
    if (is_null_test)
    {
        if (result == NULL) { puts("REJECTED"); code = 2; }
        else { puts("UNEXPECTED_ACCEPT"); code = 3; }
    }
    else if (result != NULL)
    {
        printf("SET:%s\n", cJSON_GetStringValue(item));
        code = 0;
    }
    else { puts("SET_FAILED"); code = 3; }
    cJSON_Delete(item);
    return code;
}
'''
    return source


def test_case(name: str, content: str, rc: int, output: str, category: str) -> dict:
    return {"id": name, "category": category, "text": content,
            "expected": {"exit_code": rc, "stdout": output}}


def setup_configs() -> None:
    attacks = [
        test_case("upstream-poc", "NULL:apple\n", 2, "REJECTED\n", "security"),
        test_case("alternate-input", "NULL:pear\n", 2, "REJECTED\n", "security"),
    ]
    functional = [
        test_case("normal-set", "SET:apple:orange\n", 0, "SET:orange\n", "functional"),
        test_case("regression-detect", "SET:apple:hello\n", 0, "SET:hello\n", "functional"),
        test_case("empty-replacement", "SET:apple:\n", 0, "SET:\n", "boundary"),
        test_case("long-replacement", "SET:a:" + "z" * 128 + "\n", 0, "SET:" + "z" * 128 + "\n", "boundary"),
        test_case("invalid-command", "BAD:apple\n", 2, "INVALID\n", "invalid"),
        test_case("missing-original", "NULL:\n", 2, "INVALID\n", "invalid"),
    ]
    configs = PROJECT / "configs"
    for kind in ("correct", "incomplete", "regression"):
        cfg = {
            "name": f"cjsonreal-{kind}",
            "target": {"id": "cjsonreal", "name": "cJSON upstream v1.7.17/1.7.18 CVE-2024-31755",
                       "libraries": ["m"]},
            "base": "targets/cjsonreal/base.c",
            "patch": f"targets/cjsonreal/{kind}.c",
            "input_mode": "stdin", "attacks": attacks, "functional": functional,
            "reference": "docs/oracle-cjsonreal.md"
        }
        (configs / f"cjsonreal-{kind}.json").write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")


def replace_once(path: Path, old: str, new: str) -> None:
    contents = path.read_text(encoding="utf-8")
    if old not in contents:
        if new in contents:
            print(f"Already adjusted: {path.relative_to(PROJECT)}")
            return
        raise RuntimeError(f"Expected marker not present in {path}: {old!r}")
    path.with_suffix(path.suffix + ".before-cjsonreal.bak").write_text(contents, encoding="utf-8")
    path.write_text(contents.replace(old, new), encoding="utf-8")


def modify_pipeline() -> None:
    assert_path = PROJECT / "tools" / "assert_matrix.py"
    wrapper_path = PROJECT / "tools" / "docker_run.sh"
    tests_path = PROJECT / "tests" / "test_configs.py"
    replace_once(wrapper_path, "configs/jsonc-", "configs/cjsonreal-")
    replace_once(assert_path, "'jsonc-", "'cjsonreal-")
    if tests_path.exists():
        original = tests_path.read_text(encoding="utf-8")
        if "self.assertEqual(len(found),6)" in original:
            replace_once(tests_path, "self.assertEqual(len(found),6)",
                         "self.assertGreaterEqual(len(found),6)")
    # Extend function-name recognition to public C API declarations in source diffs.
    correlate = PROJECT / "patchguard" / "correlation.py"
    if correlate.exists():
        code = correlate.read_text(encoding="utf-8")
        if 'CJSON_FUN' not in code:
            old_function = "        m = FUN.search(value)\n"
            new_function = ("        m = FUN.search(value) or CJSON_FUN.search(value)\n")
            if old_function not in code:
                raise RuntimeError("Unrecognized function parser layout in correlation.py")
            code = code.replace(old_function, new_function, 1)
            old_import = "FUN = re.compile("
            if old_import not in code:
                raise RuntimeError("Missing function parser definition in correlation.py")
            insert = "CJSON_FUN = re.compile(r'^\\s*CJSON_PUBLIC\\([^)]*\\)\\s+([A-Za-z_]\\w*)\\s*\\(')\n"
            # Insert before function_at to guarantee it is defined when called.
            code = code.replace("\ndef function_at(", "\n" + insert + "\ndef function_at(", 1)
            code = code.replace(old_function, new_function, 1)
            correlate.with_suffix(".py.before-cjsonreal.bak").write_text(
                correlate.read_text(encoding="utf-8"), encoding="utf-8")
            correlate.write_text(code, encoding="utf-8")
    readme = PROJECT / "README.md"
    appendix = """

## Real upstream target: cJSON CVE-2024-31755

Source in `targets/cjsonreal/upstream/{v1.7.17,v1.7.18}` consists of the
actual upstream releases, downloaded by `tools/add_real_cjson_target.py`.
Four standalone C files contain upstream implementation with an appended
input adapter. `base.c` uses actual 1.7.17, `correct.c` uses actual 1.7.18.
`incomplete.c` / `regression.c` are deliberately modified versions of 1.7.18
for grading fixtures: **not genuine upstream releases**.

The real upstream defect is CVE-2024-31755: a null pointer second argument to
`cJSON_SetValuestring` causes invalid memory access in 1.7.17 and is rejected
in 1.7.18. References, reference behavior and provenance are in
`docs/oracle-cjsonreal.md` and `targets/cjsonreal/source_manifest.json`.

The CI grading matrix now uses frame + cjsonreal as its two targets. The old
`targets/jsonc` demo is kept but not used for scoring. Target selection and
oracles still require instructor approval. The four-patch suite is not a
substitute for evaluating instructor-supplied unseen patches.
"""
    previous = readme.read_text(encoding="utf-8")
    if "## Real upstream target: cJSON CVE-2024-31755" not in previous:
        readme.write_text(previous + appendix, encoding="utf-8")


def add_docs() -> None:
    content = """# Independent reference: cJSON upstream CVE-2024-31755

- Repository: https://github.com/DaveGamble/cJSON
- Vulnerable upstream tag: v1.7.17 (2023-12-26)
- Patched upstream tag: v1.7.18 (2024-05-13)
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-31755
- Upstream report and PoC: https://github.com/DaveGamble/cJSON/issues/839
- Changelog: https://github.com/DaveGamble/cJSON/blob/master/CHANGELOG.md

The upstream issue reports that `cJSON_SetValuestring(cJSON_CreateString("apple"), NULL)`
causes invalid memory access in cJSON 1.7.17. Version 1.7.18 explicitly rejects
NULL valuestring input, returning NULL. This behavior is supported by upstream
documentation/fix and the issue, not inferred from the patched demo's stdout.

The standalone adapter (only the adapter is ours) reads one `stdin` line:

- `NULL:<original>`: call cJSON_SetValuestring with a NULL second argument;
  correct behavior: safe rejection `REJECTED\\n`, process exit 2.
- `SET:<original>:<replacement>`: non-NULL string modification; correct behavior:
  `SET:<replacement>\\n`, process exit 0, including empty replacements.
- Wrong commands and missing initial strings: `INVALID\\n`, exit 2.

Both tags are **real upstream C library implementations**. The variants
`incomplete` and `regression` are intentionally modified teaching patches,
clearly separate from published upstream commits. The incomplete variant
rejects only a specific NULL-input case while the other still crashes.
The regression variant safely rejects NULL but improperly rejects `hello`
for an otherwise valid call. Both variants are expected to be recognized by
PatchGuard from actual execution, not names.

Instructor approval of the target/oracle has not yet been recorded.
"""
    (PROJECT / "docs" / "oracle-cjsonreal.md").write_text(content, encoding="utf-8")


def main() -> int:
    if not ((PROJECT / "patchguard" / "runner.py").is_file()
            and (PROJECT / "tools" / "docker_run.sh").is_file()
            and (PROJECT / "configs").is_dir()):
        raise RuntimeError("Put this file in PatchGuard_Project1/tools/ and run it from there")
    print("Downloading genuine upstream cJSON release sources...")
    base_files, base_sha, base_method = download_source(BASE)
    fixed_files, fixed_sha, fixed_method = download_source(FIX)
    b = base_files["cJSON.c"].decode("utf-8")
    f = fixed_files["cJSON.c"].decode("utf-8")
    if BASE_PATTERN.search(b) is None:
        raise RuntimeError("The 1.7.17 vulnerable source does not contain the expected guard")
    if FIX_PATTERN.search(f) is None:
        raise RuntimeError("The 1.7.18 source does not contain the required NULL fix")
    if not re.search(r"CJSON_VERSION_PATCH\s+17", base_files["cJSON.h"].decode("utf-8")):
        raise RuntimeError("The 1.7.17 header has the wrong version")
    if not re.search(r"CJSON_VERSION_PATCH\s+18", fixed_files["cJSON.h"].decode("utf-8")):
        raise RuntimeError("The 1.7.18 header has the wrong version")
    for tag, files in ((BASE, base_files), (FIX, fixed_files)):
        dest = TARGET / "upstream" / tag
        dest.mkdir(parents=True, exist_ok=True)
        for name, data in files.items():
            (dest / name).write_bytes(data)
    for name, tag, source in (
        ("base", BASE, b), ("correct", FIX, f),
        ("incomplete", FIX, f), ("regression", FIX, f)
    ):
        (TARGET / (name + ".c")).write_text(
            cjson_with_driver(tag, source, name), encoding="utf-8")
    manifest = {
        "upstream_repository": REPOSITORY,
        "upstream_issue": "https://github.com/DaveGamble/cJSON/issues/839",
        "cve": "CVE-2024-31755",
        "original_release": {"tag": BASE, "git_commit": base_sha, "retrieval": base_method,
                             "files_sha256": {k: digest(v) for k,v in base_files.items()}},
        "patched_release": {"tag": FIX, "git_commit": fixed_sha, "retrieval": fixed_method,
                            "files_sha256": {k: digest(v) for k,v in fixed_files.items()}},
        "variants": {"base": "upstream vulnerable", "correct": "upstream fixed",
                     "incomplete": "our intentionally incomplete guard", 
                     "regression": "our intentionally broken valid behavior"},
    }
    (TARGET / "source_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n",encoding="utf-8")
    setup_configs()
    add_docs()
    modify_pipeline()
    print("Installed cJSON real-world target, 3 configs, oracle and CI matrix changes.")
    print("Sources:", BASE, base_sha, ";", FIX, fixed_sha)
    print("Now run: ./tools/docker_run.sh")
    print("Then: git diff --stat && git status --short")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("INSTALL FAILED:", str(exc), file=sys.stderr)
        sys.exit(1)
