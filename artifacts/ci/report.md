# PatchGuard Verification Report

Repository revision: `dee1cbfa0e86e3e902e84283b1707e55cb19cd0e`

| Scenario | Security | Functionality | Complete | Exit |
|---|---|---|---|---:|
| frame-correct | fixed | pass | True | 0 |
| frame-incomplete | incomplete | pass | True | 10 |
| frame-regression | fixed | regression | True | 20 |
| cjsonreal-correct | fixed | pass | True | 0 |
| cjsonreal-incomplete | incomplete | pass | True | 10 |
| cjsonreal-regression | fixed | regression | True | 20 |

**Overall CI result:** FUNC_REGRESSION (20)

## frame-correct
- Correlation: function_overlap — runtime stack-frame function contains patch changes
- Hardening changes: none observed
- Reproduction bundles: 2
- Attack `initial-exploit`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `bypass-input`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `reg-bypass-input-29e16573b460`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `reg-initial-exploit-28721cd6522a`: base `confirmed`, patch `absent`, patch reference `True`
- Function `empty`: baseline `True`, patch `True`
- Function `five`: baseline `True`, patch `True`
- Function `max-valid`: baseline `True`, patch `True`
- Function `short`: baseline `True`, patch `True`

## frame-incomplete
- Correlation: function_overlap — runtime stack-frame function contains patch changes
- Hardening changes: none observed
- Reproduction bundles: 2
- Attack `initial-exploit`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `bypass-input`: base `confirmed`, patch `confirmed`, patch reference `False`
- Attack `reg-bypass-input-29e16573b460`: base `confirmed`, patch `confirmed`, patch reference `False`
- Attack `reg-initial-exploit-28721cd6522a`: base `confirmed`, patch `confirmed`, patch reference `False`
- Function `empty`: baseline `True`, patch `True`
- Function `five`: baseline `True`, patch `True`
- Function `max-valid`: baseline `True`, patch `True`
- Function `short`: baseline `True`, patch `True`

## frame-regression
- Correlation: function_overlap — runtime stack-frame function contains patch changes
- Hardening changes: none observed
- Reproduction bundles: 2
- Attack `initial-exploit`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `bypass-input`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `reg-bypass-input-29e16573b460`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `reg-initial-exploit-28721cd6522a`: base `confirmed`, patch `absent`, patch reference `True`
- Function `empty`: baseline `True`, patch `True`
- Function `five`: baseline `True`, patch `False`
- Function `max-valid`: baseline `True`, patch `True`
- Function `short`: baseline `True`, patch `True`

## cjsonreal-correct
- Correlation: function_overlap — runtime stack-frame function contains patch changes
- Hardening changes: none observed
- Reproduction bundles: 2
- Attack `upstream-poc`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `alternate-input`: base `confirmed`, patch `absent`, patch reference `True`
- Function `normal-set`: baseline `True`, patch `True`
- Function `regression-detect`: baseline `True`, patch `True`
- Function `empty-replacement`: baseline `True`, patch `True`
- Function `long-replacement`: baseline `True`, patch `True`
- Function `invalid-command`: baseline `True`, patch `True`
- Function `missing-original`: baseline `True`, patch `True`

## cjsonreal-incomplete
- Correlation: function_overlap — runtime stack-frame function contains patch changes
- Hardening changes: none observed
- Reproduction bundles: 2
- Attack `upstream-poc`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `alternate-input`: base `confirmed`, patch `confirmed`, patch reference `False`
- Attack `reg-alternate-input-7feab1881767`: base `confirmed`, patch `confirmed`, patch reference `False`
- Attack `reg-upstream-poc-cdc92270f196`: base `confirmed`, patch `confirmed`, patch reference `False`
- Function `normal-set`: baseline `True`, patch `True`
- Function `regression-detect`: baseline `True`, patch `True`
- Function `empty-replacement`: baseline `True`, patch `True`
- Function `long-replacement`: baseline `True`, patch `True`
- Function `invalid-command`: baseline `True`, patch `True`
- Function `missing-original`: baseline `True`, patch `True`

## cjsonreal-regression
- Correlation: function_overlap — runtime stack-frame function contains patch changes
- Hardening changes: none observed
- Reproduction bundles: 2
- Attack `upstream-poc`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `alternate-input`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `reg-alternate-input-7feab1881767`: base `confirmed`, patch `absent`, patch reference `True`
- Attack `reg-upstream-poc-cdc92270f196`: base `confirmed`, patch `absent`, patch reference `True`
- Function `normal-set`: baseline `True`, patch `True`
- Function `regression-detect`: baseline `True`, patch `False`
- Function `empty-replacement`: baseline `True`, patch `True`
- Function `long-replacement`: baseline `True`, patch `True`
- Function `invalid-command`: baseline `True`, patch `True`
- Function `missing-original`: baseline `True`, patch `True`

Scope: observed dynamic behavior on declared inputs and build configurations only.
A finding/diff overlap is evidence of correlation, not proof of causality or global absence of vulnerabilities.
