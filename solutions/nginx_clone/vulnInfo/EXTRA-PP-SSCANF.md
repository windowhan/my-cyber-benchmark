---
id: "EXTRA-PP-SSCANF"
title: "PROXY-protocol header parsing (unvalidated sscanf)"
severity: "planted-extra"
planted: true
cwe: ["CWE-120"]
modeled_on: "PROXY-protocol header parsing (unvalidated sscanf)"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-PP-SSCANF — PROXY-protocol header parsing (unvalidated sscanf)

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-120
- **Modeled on:** PROXY-protocol header parsing (unvalidated sscanf)
- **Site:** `?` → `?`

## Description

sscanf result unchecked; malformed PROXY lines leave src/dst uninitialised while the header is still consumed

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-PP-SSCANF`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
