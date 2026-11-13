---
id: "EXTRA-XSLT-PI"
title: "Bounded include buffer"
severity: "planted-extra"
planted: true
cwe: ["CWE-120"]
modeled_on: "bounded include buffer"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-XSLT-PI — Bounded include buffer

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-120
- **Modeled on:** bounded include buffer
- **Site:** `src/mod/snx_mod_image.c` → `snx_f_xslt_body`

## Description

stylesheet bytes cpymem into pi[512] at +22 with n up to 512 -> stack overflow for large .xsl.

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-XSLT-PI`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
