# Target approval sheet - Action required before claiming full compliance

Course: Data and Network Security, Project 1, Sharif University of Technology.

Group: Poorya Amirniya; Danial Azarnia; Mohammad Javad Khoshdouni Farahani; Mohammad Matin Ansari.

## Proposed teaching target 1 - Frame parser

Original C executable parsing `MSG:<payload>`, a bounded 16-byte stack buffer, with explicitly defined correctness and invalid input behavior (`docs/oracle-frame.md`). Includes base, correct fix, intentionally incomplete fix, and functional regression fix. Pre- and post-patch crashes are measured by real ASan with source-level stack frames.

## Proposed target 2 - JSON note processing using json-c

C executable parsing actual JSON using the well-established `json-c` C library. The implementation, four variants, independently specified behavior, and test inputs are in `targets/jsonc` and `docs/oracle-jsonc.md`. json-c is a real production library, but the example vulnerability was deliberately introduced into the application **integrating** json-c, not found in upstream json-c. We must not market this as a json-c CVE or upstream patch.

## Requested decisions from instructor

1. Are these target choices approved as satisfying the two independent targets requirement (including the genuine non-toy target requirement)? If not, an upstream historical vulnerable library/application and genuine patch must replace the JSON demonstration.
2. Are the independently stated behavior oracles (valid, boundary, invalid input, stdout and exit status) accepted?
3. Is the agreed interface `stdin` and the scoped attack space adequate for unseen-patch evaluation?

No instructor approval has been received or claimed. Until answered, do not claim 100/100 rubric conformity. When replacing either target, modify its config and source files; classification/correlation/minimization logic is not keyed to target source function names.
