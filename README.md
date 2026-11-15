# PatchGuard - Security Patch Validation + Regression Testing in CI/CD

Data and Network Security — Sharif University of Technology — Project 1.

Group: Poorya Amirniya, Danial Azarnia, Mohammad Javad Khoshdouni Farahani, Mohammad Matin Ansari.

A self-contained, executable **educational demonstration** of source-diff-to-dynamic-finding correlation, ASan/UBSan, reproducible crashing input minimization, security patch verification, functional regression testing, ELF hardening, and structured CI exit codes.

## Requirements

Linux x86-64 with `python3`, `gcc`, `binutils`, `git`, `libjson-c-dev`; optionally Docker. Tested locally on a Linux development container. The demo binaries intentionally contain memory-safety defects and **must not be run outside a disposable/isolated environment**.

### Recommended: Docker

```bash
chmod +x tools/docker_run.sh
./tools/docker_run.sh
```

This builds a restricted Docker image, runs six scenarios, asserts their expected outcomes and stores output in `artifacts/ci/report.json`, `artifacts/ci/report.md`, `artifacts/ci/repro/`, `artifacts/ci/regression/`.

### Local disposable Linux VM only

```bash
sudo apt-get install -y gcc python3 binutils git libjson-c-dev
python3 -m patchguard --allow-local --config configs/frame-correct.json --out artifacts/frame-good
printf 'exit code: %s\n' "$?"
python3 -m patchguard --allow-local --config configs/frame-incomplete.json --out artifacts/frame-incomplete
printf 'exit code: %s\n' "$?"
python3 -m patchguard --allow-local --config configs/frame-regression.json --out artifacts/frame-regression
printf 'exit code: %s\n' "$?"
```

Results: 0 correct patch; 10 incomplete patch; 20 functional regression. Same matrix for `jsonc` target; use `tools/assert_matrix.py` after batch evaluation. Normal release and sanitized binaries, output streams, exit signals/codes, ELF analysis and git diff are captured separately.

## Layout

- `patchguard/` - generic CLI engine, build/run, sanitizer detection, correlation, minimization, ELF hardening.
- `targets/frame/` - purpose-built frame parser in C (one of two independent programs).
- `targets/jsonc/` - separate JSON note store in C using the real json-c C library.
- `configs/` - base/patch source pairs, attack/functional inputs and independent behavior oracle.
- `docs/oracle-*.md` - independently declared correct behavior for valid/invalid inputs.
- `docs/architecture.md` - decisions, limitations and threat model.
- `docs/defense-fa.md` - Persian oral-defense preparation.
- `tests/` - fast pure logic and integration testing.
- `regressions/` - automatically promoted minimized crashing inputs, replayed on every later run.
- `.github/workflows/` - automated restricted Docker runner and artifact publication.

## Important honesty / instructor approval

The two C programs and four variants per program are included and runnable. The second uses a production C library (`json-c`), **but the vulnerability is in the local application integration rather than an upstream json-c release**; the first is a teaching target. The assignment requires that at least one target be a genuine non-toy upstream project/library. Instructor **approval of the target selection and independent oracles has not been obtained**. This version demonstrates the entire pipeline but **must not be represented as meeting that upstream-target requirement without approval or replacement with an accepted upstream real-world target**.

Approval sheet: `docs/instructor-approval.md`. Reference: `docs/architecture.md`. Nothing in the results establishes absence of unknown vulnerabilities or exploits.

## Replay a minimized crash

From a **disposable Linux container/VM only**:

```bash
PYTHONPATH=. python3 tools/replay.py artifacts/ci/repro/frame-correct/initial-exploit/manifest.json --allow-local
```

This rebuilds the vulnerable sanitized ELF from the checked-in C source, reruns the minimized case 3 times, and checks both the original ASan error category and target application frame. It prints source/binary hashes so replays can be audited; binary hashes may differ across compiler/toolchain versions and source paths. Don't use `--allow-local` on a normal workstation.


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
