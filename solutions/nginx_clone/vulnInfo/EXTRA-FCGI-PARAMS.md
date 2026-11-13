---
id: "EXTRA-FCGI-PARAMS"
title: "CVE-2013-2070 / fastcgi param packing class"
severity: "planted-extra"
planted: true
cwe: ["['CWE-121']"]
modeled_on: "CVE-2013-2070 / fastcgi param packing class"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-FCGI-PARAMS — CVE-2013-2070 / fastcgi param packing class

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** ['CWE-121']
- **Modeled on:** CVE-2013-2070 / fastcgi param packing class
- **Site:** `src/mod/snx_mod_upstream.c` → `?`

## Description

new-feature module, not one of the canonical 68

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-FCGI-PARAMS`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
