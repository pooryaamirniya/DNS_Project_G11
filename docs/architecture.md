# Architecture and threat model

1. `configs/*.json` describe each before/after source pair, attack payloads, build libraries, and independent reference outputs. No source function names or variant name are used to choose outcomes.
2. `runner.build` produces matching GCC `release` and `sanitized` binaries for each version; hashes and exact command lines are recorded.
3. `runner.run` starts real ELF processes with controlled stdin. The tool parses ASan/UBSan reports and separately records OS signals, exit status, timeout, stdout and stderr.
4. Security attacks run three times for each version; only matching sanitizer type + application function count as confirmed. Mixed observations cause INCONCLUSIVE.
5. Valid functional tests compare both versions with a reference contract independent of patched output. Valid baseline pass + patched mismatch => REGRESSION.
6. `correlation` runs `git diff --no-index -U0` and maps sanitizer application stack frames onto changed hunk functions/lines. Unknown correlation is explicit, not fabricated. It provides empirical relationship, not causality proof.
7. `minimize` performs byte-level delta debugging, preserving both vulnerability class and application function. `repro` stores input, minimum, 3 replays, compiler args, git hash, binary and source SHA-256 and exact environment. Regression input files are generated from minimized reproductions both in run artifacts and in a canonical `regressions/<target>/` directory. This directory is automatically scanned in subsequent evaluation runs, so learned inputs become dynamic regression tests. Check it into Git or restore it from the CI cache to retain cases across clean checkouts.
8. `hardening` reads release ELF file headers, program headers, dynamic tags and symbol table via readelf to report NX/PIE/RELRO/canary. Canaries indicated by symbol do not guarantee all functions protected. PIE does not prove runtime ASLR.
9. CI treats 10 and 20 of intentional negative fixtures as expected *test outcomes*. The separate assertion script checks the matrix, failing CI for unexpected behavior.

## Security boundary

Untrusted compiled executables must run in an isolated, restricted container or disposable VM. `tools/docker_run.sh` disables networking, drops Linux capabilities, sets no-new-privileges, CPU/memory/PID limits and read-only container image, with only the checkout writable. The command-line tool refuses local execution unless `--allow-local` is deliberately provided. Do not use `--allow-local` on a host containing sensitive data. Asan may require more memory than the suggested limits for some targets; changing limits should be documented.

## Known scope limitations

- The provided runner currently targets Linux x86-64, GCC and stdin mode with a single `.c` file per variant; for external tools the build and input adapters should be expanded. The JSON payload keeps test configuration distinct from core classification logic.
- Correlation by shared function is supporting evidence only. The code intentionally does not assert that new issues are necessarily caused by the patch.
- Requires instructor approval for the target choice and oracles. A real upstream release and public patch is not bundled; the json-c integration demonstrates a real library but the intentional bug was introduced in test integration code. The rubric may demand a different genuine upstream target.
- An all-green report means scoped test success, not global security proof.

The runner also supports JSON-selected `input_mode` values `argv` and `file`, and optional arrays of `target.build_commands` (with `{source}`, `{binary}`, `{root}` placeholders) to handle other C/C++ build systems without changing the classification logic. Matching pre/post release and sanitized commands should be provided. A per-version compiler-flag override can demonstrate ELF hardening degradation and is transparently reported.
