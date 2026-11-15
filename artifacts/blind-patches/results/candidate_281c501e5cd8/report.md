# PatchGuard Verification Report

Repository revision: `dee1cbfa0e86e3e902e84283b1707e55cb19cd0e`

| Scenario | Security | Functionality | Complete | Exit |
|---|---|---|---|---:|
| candidate_281c501e5cd8 | new_issue | pass | True | 10 |

**Overall CI result:** VULN_REMAINS_OR_NEW_ISSUE (10)

## candidate_281c501e5cd8
- Correlation: function_overlap — runtime stack-frame function contains patch changes
- Hardening changes: none observed
- Reproduction bundles: 0
- Attack `initial-exploit`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `bypass-input`: base `confirmed`, patch `confirmed`, patch reference `False`
- Attack `reg-bypass-input-29e16573b460`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `reg-initial-exploit-28721cd6522a`: base `confirmed`, patch `absent`, patch reference `True`
- Function `empty`: baseline `True`, patch `True`
- Function `five`: baseline `True`, patch `True`
- Function `max-valid`: baseline `True`, patch `True`
- Function `short`: baseline `True`, patch `True`

Scope: observed dynamic behavior on declared inputs and build configurations only.
A finding/diff overlap is evidence of correlation, not proof of causality or global absence of vulnerabilities.
