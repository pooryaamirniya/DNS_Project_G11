# PatchGuard Verification Report

Repository revision: `dee1cbfa0e86e3e902e84283b1707e55cb19cd0e`

| Scenario | Security | Functionality | Complete | Exit |
|---|---|---|---|---:|
| candidate_3554eeb55e83 | inconclusive | pass | False | 40 |

**Overall CI result:** INCONCLUSIVE (40)

## candidate_3554eeb55e83
- Correlation: function_overlap — runtime stack-frame function contains patch changes
- Hardening changes: none observed
- Reproduction bundles: 0
- Attack `no-verified-baseline-crash`: base `absent`, patch `absent`, patch reference `True`
- Attack `reg-bypass-input-29e16573b460`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `reg-initial-exploit-28721cd6522a`: base `confirmed`, patch `absent`, patch reference `True`
- Function `empty`: baseline `True`, patch `True`
- Function `five`: baseline `True`, patch `True`
- Function `max-valid`: baseline `True`, patch `True`
- Function `short`: baseline `True`, patch `True`

Scope: observed dynamic behavior on declared inputs and build configurations only.
A finding/diff overlap is evidence of correlation, not proof of causality or global absence of vulnerabilities.
