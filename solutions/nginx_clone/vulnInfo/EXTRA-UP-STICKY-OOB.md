---
id: "EXTRA-UP-STICKY-OOB"
title: "Sticky session index trust"
severity: "planted-extra"
planted: true
cwe: ["CWE-125"]
modeled_on: "sticky session index trust"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-UP-STICKY-OOB — Sticky session index trust

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-125
- **Modeled on:** sticky session index trust
- **Site:** `src/mod/snx_mod_upstream.c` → `snx_upstream_pick`

## Description

client Cookie srv=<idx> indexes peers[] verbatim -> OOB read. Live: Cookie srv=9 on /st/ -> ASan heap-use-after-free.

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-UP-STICKY-OOB`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
