# CI fix: dynamically generated regression cases

Both GitHub Actions workflows originally ran unit tests before the six-scenario matrix. The `test_learned_cases_are_loaded_for_subsequent_pipelines` test requires at least two persisted minimized inputs in `regressions/<target>/`, but the directory is not populated on a fresh checkout. The initial test additionally hard-coded the obsolete target `jsonc` whereas the current six-scenario matrix uses `cjsonreal`.

Fixes:

1. Run `tools/docker_run.sh` first, generating canonical minimized regression cases in `regressions/frame/` and `regressions/cjsonreal/` through the mounted Docker worktree.
2. Run regression-loader tests after the corpus is present.
3. Change the target list in `tests/test_configs.py` to `('frame', 'cjsonreal')`, preserving the original expectation of two or more learned cases and valid exit-code reference behavior.
4. Keep blind tests and independent Quality Gate in the full workflow.
5. Restore/save the verified regression corpus with GitHub Actions cache, preserving the original cross-run learning behavior.

The *intentional* `Quality Gate: FAIL` messages printed by negative-path unit tests are not themselves workflow failures. The actual logged failure is `AssertionError: 0 not greater than or equal to 2`.

## Install on WSL

From the project folder:

```bash
cd /mnt/c/Users/poory/Downloads/PatchGuard_Project1
python3 -m zipfile -e ../PatchGuard_CI_Fix_Stage6.zip .
python3 tools/publish_github.py
```

This ZIP contains only `tests/test_configs.py`, two workflow files, and this documentation. No target source, classifier, or security oracle changes. The existing publisher uses non-force Git push.

After publishing, inspect the new GitHub Actions runs with:

```bash
gh run list -R pooryaamirniya/DNS_Project_G11 --limit 6
gh run view RUN_ID -R pooryaamirniya/DNS_Project_G11 --log-failed
```

This fixes the identified test/corpus mismatch but does not prove the full hosted workflows have passed. Investigate any additional job failures using their logs.
