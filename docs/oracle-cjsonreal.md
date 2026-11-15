# Independent reference: cJSON upstream CVE-2024-31755

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
  correct behavior: safe rejection `REJECTED\n`, process exit 2.
- `SET:<original>:<replacement>`: non-NULL string modification; correct behavior:
  `SET:<replacement>\n`, process exit 0, including empty replacements.
- Wrong commands and missing initial strings: `INVALID\n`, exit 2.

Both tags are **real upstream C library implementations**. The variants
`incomplete` and `regression` are intentionally modified teaching patches,
clearly separate from published upstream commits. The incomplete variant
rejects only a specific NULL-input case while the other still crashes.
The regression variant safely rejects NULL but improperly rejects `hello`
for an otherwise valid call. Both variants are expected to be recognized by
PatchGuard from actual execution, not names.

Instructor approval of the target/oracle has not yet been recorded.
