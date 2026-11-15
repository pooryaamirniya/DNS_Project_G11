# PatchGuard architecture, evidence, and security boundary

## End-to-end evaluation

1. A JSON configuration identifies the baseline C/C++ source, candidate source, input mode, build options, attack inputs, functional cases, and **independent** expected outputs.
2. `runner.build` compiles comparable **release** and **sanitized** ELF binaries (pre-patch and post-patch), retaining commands, compiler status and SHA-256 evidence.
3. `runner.run` executes the binaries with controlled inputs. `detection` records ASan/UBSan findings separately from OS signals, return codes, stdout/stderr, resource limits and timeouts.
4. Attack cases are replayed **three times per version**. Stable matching sanitizer signatures are confirmed; unstable and unclassified outcomes become `INCONCLUSIVE`, not invented vulnerabilities.
5. Sanitizer source frames are selected from application C/C++ code where the traceback supports them; paths do **not** need to contain `/targets/`. For a confirmed persisted defect, type/function evidence is compared across versions. This is a heuristic and is limited by traceback quality.
6. Functional tests compare baseline and patched *release* builds with the independent expected behavior. If baseline passes but candidate fails, the result is `FUNC_REGRESSION`.
7. `correlation` compares changed source hunks and actual runtime evidence. Function overlap is a useful supporting signal; it is **not** proof that the changed line caused a crash.
8. `minimize` performs delta debugging while preserving the selected crash signature. Reproducer bundles include the input, minimization trials, replays, source and binary hashes, build commands, environment and revision; automatically learned cases are stored under `regressions/<target>/`.
9. `hardening` uses ELF inspection to evaluate NX, PIE, RELRO and stack-canary indicators. These are indicators, not guarantees of complete exploit protection.
10. GitHub Actions run the six-case expected-result matrix, unit tests, nine generated blind variants and strict Quality Gate. Since one unit test checks persisted regression cases, **the six-case run precedes the unit suite on a fresh checkout**.

## Current target matrix

- `frame`: original educational C frame parser.
- `cjsonreal`: genuine cJSON upstream v1.7.17 / v1.7.18 source for CVE-2024-31755, tested through a local stdin adapter. Incomplete and regression variants are purpose-made negative fixtures, **not** upstream releases.
- `targets/jsonc/`: older integration demonstration kept for reference, not graded in the official matrix.

Source provenance and SHA-256 details for the upstream cJSON target are in `targets/cjsonreal/source_manifest.json`. Input/output specifications are `docs/oracle-frame.md` and `docs/oracle-cjsonreal.md`. Approval of these target choices and oracles remains an **instructor/TA decision**; do not claim approval unless recorded in `docs/instructor-approval.md`.

## Security boundary

Intentionally vulnerable native binaries should run **only in a restricted container or disposable VM**. The Docker runner disables networking, drops capabilities, enables no-new-privileges, and applies resource limits and a read-only image. The checkout bind mount is writable for evidence outputs. Local unrestricted execution requires explicitly opting into `--allow-local`; do not run it on an everyday workstation holding sensitive data.

## Known limitations

- Results apply to the particular test corpus, toolchain, source files, runner configuration and observed execution only.
- The bundled target adapters are intentionally small and use a known stdin contract. Support for arbitrary upstream projects, multi-target build systems and differing interfaces may require configuration/build-adapter work; do not promise arbitrary C/C++ builds work without adaptation.
- Stack-trace function resolution and diff correlation are imperfect, especially with stripped binaries, inlining, optimized code or frames lacking debug symbols.
- Successful ASan/UBSan checks do not prove a program is globally free of vulnerabilities.
- Generated blind variants test classification independence from known filenames, **not** every possible unseen patch supplied by an instructor.
- Persisted regressions created during a run may need to be committed or restored between clean runners; CI uses an appropriate ordering/cache strategy.
