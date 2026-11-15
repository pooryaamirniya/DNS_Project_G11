# Independently specified behavior: JSON note store (json-c integration)

Input: a JSON object from `stdin` with string fields `user` and `note`.
A valid `note` contains 0..23 bytes (the sample cases use ASCII). Valid input prints `SAVED:<user>:<note>\n` and exits 0. Missing/non-string fields or notes over 23 bytes print `INVALID\n` and exit 2. The demonstration uses json-c (a real, production C JSON library), but the vulnerability is **in the local integration code**, not in upstream json-c. This distinction must be disclosed when seeking teacher approval.

The intended oracle predates evaluation; neither current patched output nor an LLM response is the truth source.
