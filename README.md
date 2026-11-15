# PatchGuard

**Automated security patch validation and functional regression testing for Linux ELF programs**
Sharif University of Technology · Data & Network Security · Project 1 · Group 11

**Team:** Poorya Amirniya · Danial Azarnia · Mohammad Javad Khoshdouni Farahani · Mohammad Matin Ansari

PatchGuard builds a vulnerable baseline and a candidate patched version of a C/C++ target, executes the same inputs against both, analyzes AddressSanitizer / UndefinedBehaviorSanitizer findings, compares functional behavior against an independently specified oracle, correlates findings with source changes, and records reproducible evidence for CI/CD.

> **Safety:** The repository deliberately includes vulnerable C sources. Execute compiled targets only inside an isolated, disposable test environment. The Docker workflow is recommended.

## Quick start (Linux x86-64 / WSL2 + Docker)

```bash
git clone https://github.com/pooryaamirniya/DNS_Project_G11.git
cd DNS_Project_G11
bash tools/docker_run.sh
python3 -m unittest discover -s tests -v
python3 tools/blind_patch_test.py
python3 tools/quality_gate.py --strict
```

**Run in this order.** The six-scenario evaluation creates minimized regression cases that the unit tests check. Docker must be available and running. You do not need to install GCC or the cJSON library on the host: the Docker image supplies the build dependencies. Python 3 and Git are required on the host.

Expected verification outcomes for the declared fixtures: `Scenario matrix PASS`, `17 tests ... OK`, `Blind patch matrix: 9/9 passed`, and `Quality Gate: PASS`. The test suite deliberately includes negative cases with nonzero PatchGuard return codes; the matrix assertion, not the raw aggregate code, determines whether the demonstration passed.

## Evaluated targets

| Target | Vulnerability | Vulnerable version | Correct version | Deliberate test variants |
|---|---|---|---|---|
| `frame` | Stack buffer overflow in a small teaching parser | `targets/frame/base.c` | `targets/frame/correct.c` | `incomplete.c`, `regression.c` |
| `cjsonreal` | cJSON `CVE-2024-31755`, NULL-pointer argument to `cJSON_SetValuestring` | upstream `v1.7.17` | upstream `v1.7.18` | `incomplete.c`, `regression.c` |

The real cJSON upstream files and their checksums are included at `targets/cjsonreal/upstream/` and `targets/cjsonreal/source_manifest.json`. The input adapter makes the public cJSON defect executable through a reproducible stdin contract. The deliberately incomplete and regression-inducing cJSON variants are **test fixtures**, not official upstream releases. See `docs/oracle-frame.md` and `docs/oracle-cjsonreal.md` for their reference behavior.

## Expected six-scenario matrix

| Scenario | Classification | Exit code |
|---|---|---:|
| `frame-correct` | PASS | 0 |
| `frame-incomplete` | Vulnerability remains | 10 |
| `frame-regression` | Functional regression | 20 |
| `cjsonreal-correct` | PASS | 0 |
| `cjsonreal-incomplete` | Vulnerability remains | 10 |
| `cjsonreal-regression` | Functional regression | 20 |

Additional exit codes are `30` for a build/configuration failure and `40` for insufficient/inconclusive evidence. The nine-case blind suite also checks those conditions and a newly introduced memory-safety issue.

## How it works

1. Parse a target-independent JSON configuration with the baseline and patched sources, build settings, attacks, functional inputs and behavioral oracle.
2. Compile **release** and **ASan/UBSan-instrumented** ELF binaries separately for each version.
3. Reproduce declared security cases three times on both versions and classify their sanitizer findings.
4. Validate ordinary and boundary-case behavior against the independent oracle, including regression detection.
5. Relate runtime application stack frames to source changes; do not claim causality if evidence is weak.
6. Minimize crash-triggering inputs while preserving the vulnerability class and implicated application function; save replay manifests, input files, hashes and compiler commands.
7. Record NX, PIE, RELRO and stack-canary indicators for the release binaries and emit JSON/Markdown verdicts.

The container runner disables networking, drops capabilities, uses `no-new-privileges`, and applies process, memory and CPU limits. It is a risk-reduction measure, not a proof of perfect sandbox isolation.

## Repository structure

| Location | Purpose |
|---|---|
| `patchguard/` | Evaluation engine (runner, detection, correlation, minimization, ELF checks, CLI) |
| `targets/frame/`, `targets/cjsonreal/` | Target sources and their versions |
| `configs/` | Six declared evaluation scenarios |
| `docs/oracle-*.md`, `docs/architecture.md` | Independent behavior contracts and technical architecture |
| `tests/` | Unit tests and regression-loader checks |
| `tools/docker_run.sh` | Six-scenario isolated evaluation |
| `tools/blind_patch_test.py` | Nine generated, unlabeled patch candidates |
| `tools/evaluate_candidate.py` | Check a new, compatible C source patch |
| `tools/quality_gate.py` | Verify stored evidence and upstream source provenance |
| `artifacts/ci/` | Six-scenario JSON/Markdown reports and reproducible crash bundles |
| `artifacts/blind-patches/`, `artifacts/quality-gate/` | Test evidence and independent quality checks |
| `.github/workflows/` | Automated CI pipelines |
| `docs/PROJECT_REPORT_FA.pdf` | Full technical report (Persian) |

## Evaluate a new candidate

The candidate must be a **compatible C source file** inside this checkout, with the same target input adapter and build interface:

```bash
python3 tools/evaluate_candidate.py --target cjsonreal --source candidate_sources/changed.c
```

This evaluates an actual candidate rather than looking up a verdict by filename; depending on its behavior, the tool can return 0, 10, 20, 30, or 40. A new build system or input interface may need an adapted JSON build configuration.

## Evidence and scope

- Structured output: `artifacts/ci/report.json`.
- Reviewer-readable output: `artifacts/ci/report.md`.
- Reproducer manifests and original/minimized crash inputs: `artifacts/ci/repro/`.
- Blind-suite manifest, candidate sources and individual reports: `artifacts/blind-patches/`.
- Evidence integrity review: `artifacts/quality-gate/quality_report.md`.

**Limitations:** Classification is limited to tested inputs, compilers and program interfaces; source-diff overlap is correlation evidence, not causal proof. The nine generated candidates test generalization within the current target interface, not arbitrary independently authored upstream patches. ELF hardening findings describe binary properties and do not establish runtime ASLR or total exploit resistance.

## References and licensing

- [cJSON upstream repository](https://github.com/DaveGamble/cJSON)
- [CVE-2024-31755 at NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-31755)
- [cJSON changelog for v1.7.18](https://github.com/DaveGamble/cJSON/blob/master/CHANGELOG.md)
- The upstream cJSON source retains its MIT license in `targets/cjsonreal/upstream/*/LICENSE`.
