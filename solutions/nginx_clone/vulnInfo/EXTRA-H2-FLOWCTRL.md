---
id: "EXTRA-H2-FLOWCTRL"
title: "H2 flow-control window accounting"
severity: "planted-extra"
planted: true
cwe: ["CWE-190"]
modeled_on: "h2 flow-control window accounting"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-H2-FLOWCTRL — H2 flow-control window accounting

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-190
- **Modeled on:** h2 flow-control window accounting
- **Site:** `src/proto/snx_h2.c` → `DATA/WINDOW_UPDATE handlers`

## Description

DATA subtracts payload from stream/conn window with no floor check; WINDOW_UPDATE adds arbitrary increment to closed streams -> negative/overflowed window state accepted.

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-H2-FLOWCTRL`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
