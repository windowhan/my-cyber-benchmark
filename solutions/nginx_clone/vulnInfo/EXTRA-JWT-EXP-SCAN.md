---
id: "EXTRA-JWT-EXP-SCAN"
title: "JSON claim extracted by substring scan"
severity: "planted-extra"
planted: true
cwe: ["CWE-345"]
modeled_on: "JSON claim extracted by substring scan"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-JWT-EXP-SCAN — JSON claim extracted by substring scan

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-345
- **Modeled on:** JSON claim extracted by substring scan
- **Site:** `?` → `?`

## Description

payload decoded then scanned for '"exp"' anywhere; nested/quoted exp fields over-accepted

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-JWT-EXP-SCAN`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
