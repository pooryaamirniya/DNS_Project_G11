# PatchGuard Verification Report

Repository revision: `dee1cbfa0e86e3e902e84283b1707e55cb19cd0e`

| Scenario | Security | Functionality | Complete | Exit |
|---|---|---|---|---:|
| candidate_b42bca0d6d9b | fixed | pass | True | 0 |

**Overall CI result:** PASS (0)

## candidate_b42bca0d6d9b
- Correlation: function_overlap — runtime stack-frame function contains patch changes
- Hardening changes: none observed
- Reproduction bundles: 0
- Attack `upstream-poc`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `alternate-input`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `reg-alternate-input-7feab1881767`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `reg-upstream-poc-cdc92270f196`: base `confirmed`, patch `absent`, patch reference `True`
- Function `normal-set`: baseline `True`, patch `True`
- Function `regression-detect`: baseline `True`, patch `True`
- Function `empty-replacement`: baseline `True`, patch `True`
- Function `long-replacement`: baseline `True`, patch `True`
- Function `invalid-command`: baseline `True`, patch `True`
- Function `missing-original`: baseline `True`, patch `True`

Scope: observed dynamic behavior on declared inputs and build configurations only.
A finding/diff overlap is evidence of correlation, not proof of causality or global absence of vulnerabilities.
