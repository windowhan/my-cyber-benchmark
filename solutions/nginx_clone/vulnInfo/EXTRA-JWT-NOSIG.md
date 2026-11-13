---
id: "EXTRA-JWT-NOSIG"
title: "Alg:none / unsigned-token acceptance"
severity: "planted-extra"
planted: true
cwe: ["CWE-347"]
modeled_on: "alg:none / unsigned-token acceptance"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-JWT-NOSIG — Alg:none / unsigned-token acceptance

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-347
- **Modeled on:** alg:none / unsigned-token acceptance
- **Site:** `?` → `?`

## Description

signature segment decoded but never verified; any alg passes

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-JWT-NOSIG`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
