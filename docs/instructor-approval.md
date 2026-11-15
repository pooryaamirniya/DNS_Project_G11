# Instructor / TA approval record — action required

**Course:** Data and Network Security — Project 1, Sharif University of Technology  
**Group 11:** Poorya Amirniya; Danial Azarnia; Mohammad Javad Khoshdouni Farahani; Mohammad Matin Ansari.

The project requires approval of the target selections and *independent* correctness oracles. **No instructor/TA approval is claimed here until actual evidence is recorded.**

## Proposed target 1 — Frame parser (educational target)

- C ELF program: `targets/frame/`
- Versions: `base.c`, `correct.c`, `incomplete.c`, `regression.c`
- Vulnerability: reproducible stack-buffer overflow.
- Independent behavior reference: `docs/oracle-frame.md`.
- Interface: `stdin` messages using `MSG:`.

## Proposed target 2 — Real upstream cJSON library

- Repository: https://github.com/DaveGamble/cJSON
- Vulnerable release: **v1.7.17**; fixed release: **v1.7.18**.
- Historical issue: **CVE-2024-31755**, invalid access with NULL second argument to `cJSON_SetValuestring`.
- Exact upstream revisions and per-file SHA-256 hashes: `targets/cjsonreal/source_manifest.json`.
- Adapted harness: standalone C sources under `targets/cjsonreal/`; an added `stdin` adapter invokes the actual upstream implementation.
- `incomplete.c` and `regression.c` are *intentionally altered test fixtures*; they are not upstream release versions.
- Independent reference behavior: `docs/oracle-cjsonreal.md`.
- The older `targets/jsonc` integration demonstration is not part of the graded matrix.

## Decisions to obtain and record

1. Does the instructor accept `frame` + **real upstream cJSON** as the two independent targets, including the requirement for at least one non-toy target?
2. Are both independently specified oracles, input boundaries, stdout/exit-code expectations, and vulnerability reproduction criteria accepted?
3. Is the agreed `stdin` interface sufficient for demonstration of unseen patches, including compatible variants of the cJSON test adapter?

**Response from instructor/TA:** _Pending; insert only a real response and date._  
**Evidence link / approved message:** _Pending._

Even with successful GitHub Actions workflows, this approval requirement is a separate academic condition.
