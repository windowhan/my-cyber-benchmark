---
id: "EXTRA-UWSGI-PKT"
title: "Same class, uwsgi wire format"
severity: "planted-extra"
planted: true
cwe: ["['CWE-121']"]
modeled_on: "same class, uwsgi wire format"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-UWSGI-PKT — Same class, uwsgi wire format

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** ['CWE-121']
- **Modeled on:** same class, uwsgi wire format
- **Site:** `src/mod/snx_mod_upstream.c` → `?`

## Description

new-feature module

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-UWSGI-PKT`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
