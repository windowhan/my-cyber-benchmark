---
id: "EXTRA-ADDITION-LEN"
title: "Addition module length desync"
severity: "planted-extra"
planted: true
cwe: ["CWE-444"]
modeled_on: "addition module length desync"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-ADDITION-LEN — Addition module length desync

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-444
- **Modeled on:** addition module length desync
- **Site:** `src/snx_http_core.c` → `snx_http_static (addition block)`

## Description

add_before/after_body reads file capped at 65536 but cl_n += full fstat size; addition file >64KB -> Content-Length exceeds bytes sent -> client waits for remainder (response truncation/keepalive desync).

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-ADDITION-LEN`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
