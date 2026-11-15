# Independently specified behavior: Frame parser

Input: one line of bytes in `stdin`, `MSG:` prefix, 0..15 printable ASCII bytes.
Valid input prints `OK:<payload>\n` and exits 0. Invalid prefix or payload length >=16 prints `INVALID\n` and exits 2. Valid messages of lengths 0, 2, 5, 15 are the functional oracle.
This contract was written before comparing patched executable behavior. Crash inputs of lengths 24 and 32 are invalid. The vulnerable baseline violates this independent contract and gives a sanitizer memory-safety finding. The correct patch enforces the contract.

Important: this is an original pedagogical demo, not a public CVE or upstream project. Do not claim otherwise.
