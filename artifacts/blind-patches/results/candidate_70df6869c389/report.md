# PatchGuard Verification Report

Repository revision: `dee1cbfa0e86e3e902e84283b1707e55cb19cd0e`

| Scenario | Security | Functionality | Complete | Exit |
|---|---|---|---|---:|
| candidate_70df6869c389 | fixed | pass | True | 0 |

**Overall CI result:** PASS (0)

## candidate_70df6869c389
- Correlation: function_overlap — runtime stack-frame function contains patch changes
- Hardening changes: none observed
- Reproduction bundles: 0
- Attack `initial-exploit`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `bypass-input`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `reg-bypass-input-29e16573b460`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `reg-initial-exploit-28721cd6522a`: base `confirmed`, patch `absent`, patch reference `True`
- Function `empty`: baseline `True`, patch `True`
- Function `five`: baseline `True`, patch `True`
- Function `max-valid`: baseline `True`, patch `True`
- Function `short`: baseline `True`, patch `True`

Scope: observed dynamic behavior on declared inputs and build configurations only.
A finding/diff overlap is evidence of correlation, not proof of causality or global absence of vulnerabilities.
