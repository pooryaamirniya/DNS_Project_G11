# Technical architecture and evaluation boundary

PatchGuard validates security patches by **executing both the baseline and patched ELF programs** under equivalent, declared conditions. It does not infer correctness from patch filenames, predetermined answers or the patched program's output alone.

## Data flow

`Scenario JSON -> Build (release + ASan/UBSan) -> Execute baseline and patch -> Record sanitizer findings -> Compare independent oracle -> Correlate with source diff -> Minimize and replay -> Inspect ELF hardening -> JSON/Markdown + CI verdict`

1. `configs/{frame,cjsonreal}-{correct,incomplete,regression}.json` declare the source pairs, reference behavior, attack cases, functional inputs and target-specific build options.
2. `patchguard/runner.py` compiles both versions twice, keeping the optimized, hardening-enabled release ELF separate from its sanitized counterpart. It records compiler commands, binary hashes and process output.
3. `patchguard/detection.py` classifies sanitizer findings. For security inputs, three matching executions are required before the result is considered confirmed. A mere nonzero process exit is not treated as a validated memory-safety finding.
4. `patchguard/cli.py` compares security states and validates normal or boundary inputs using an independently specified oracle. A baseline-passing valid input that fails after the patch is a functional regression.
5. `patchguard/correlation.py` examines source diffs and relevant application stack frames. Overlap supports a correlation claim but cannot by itself establish causation.
6. `patchguard/minimize.py` uses input reduction while preserving the vulnerability category and application-function signature; it writes reproducible inputs and replay manifests including toolchain arguments, hashes and repeat-run evidence.
7. `patchguard/hardening.py` inspects release ELF evidence for NX, PIE, RELRO and stack-canary indicators. These observations are not equivalent to runtime exploitability proofs.
8. `patchguard/cli.py` emits structured JSON and readable Markdown. The matrix assertions explicitly expect errors in the deliberately incomplete and regressing variants.

## Targets and provenance

- `frame`: purpose-built C training target with a bounded message buffer and a reproducible stack overflow in its baseline.
- `cjsonreal`: genuine cJSON upstream code for v1.7.17 and v1.7.18. Version 1.7.17 is vulnerable to CVE-2024-31755 in `cJSON_SetValuestring`; v1.7.18 contains the upstream NULL-argument fix. Both source snapshots, their MIT license, and SHA-256 checksums are recorded in `targets/cjsonreal/upstream/` and `targets/cjsonreal/source_manifest.json`.
- Both targets contain four submitted variants: vulnerable baseline, correct patch, deliberately incomplete patch and deliberately regressing patch. The latter two cJSON variants are internal test fixtures rather than authentic vendor releases.

## Error codes

- `0`: PASS for declared security and functional cases.
- `10`: confirmed remaining vulnerability or newly observed confirmed memory-safety issue.
- `20`: functional regression.
- `30`: build or configuration error.
- `40`: inconclusive evidence.

When multiple statuses coexist, the CLI follows its documented precedence. Structured reports retain both security and functionality results so the aggregate code does not hide secondary findings.

## Reproducibility, evidence and verification

- `tools/docker_run.sh`: isolated six-scenario evaluation, followed by `tools/assert_matrix.py`.
- `tools/blind_patch_test.py`: nine generated candidate changes with unknown names, covering valid, incomplete, regression, new-issue, inconclusive and build-error cases.
- `tools/evaluate_candidate.py`: evaluate a compatible source patch without modifying the classification engine.
- `tools/quality_gate.py`: independent integrity checks over actual recorded outputs, including upstream hashes, sanitizer replay counts, regression bundles, scenario statuses and correlations.
- `.github/workflows/patchguard.yml` and `.github/workflows/quality-gate.yml`: continuous testing and evidence upload.

**Correct verification order:** six-scenario evaluation first (creates the learned regression corpus), then Python unit tests, then blind candidate tests and the strict evidence gate.

## Isolation and limitations

The Docker runner disables networking and extra capabilities, uses `no-new-privileges`, read-only container rootfs and CPU/memory/PID caps. The writable checkout mount remains part of the execution boundary; only run untrusted targets in an expendable environment. `--allow-local` is intended solely for deliberately disposable VMs or containers.

The current supplied adapters evaluate compatible C source files with declared interfaces. Unrelated build systems or deeply changed input conventions require a corresponding configuration or adapter. The nine generated candidates exercise the engine beyond its originally named variants but are not independent external patches. Dynamic tests establish scoped observed behavior, not the absence of all unknown vulnerabilities.
