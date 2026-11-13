---
id: "EXTRA-H2-DEP-CYCLE"
title: "CVE-2019-9513 h2 dependency-tree resource exhaustion"
severity: "planted-extra"
planted: true
cwe: ["CWE-674"]
modeled_on: "CVE-2019-9513 h2 dependency-tree resource exhaustion"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-H2-DEP-CYCLE — CVE-2019-9513 h2 dependency-tree resource exhaustion

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-674
- **Modeled on:** CVE-2019-9513 h2 dependency-tree resource exhaustion
- **Site:** `src/proto/snx_h2.c` → `snx_h2_dep_reparent`

## Description

PRIORITY accepts self/mutual stream dependencies; RST_STREAM reparents children by recursive walk with no cycle guard -> unbounded recursion -> stack overflow (ASan live-confirmed, pre-auth single conn).

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-H2-DEP-CYCLE`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
