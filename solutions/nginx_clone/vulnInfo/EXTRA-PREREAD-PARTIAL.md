---
id: "EXTRA-PREREAD-PARTIAL"
title: "Route decision on truncated preread prefix"
severity: "planted-extra"
planted: true
cwe: ["CWE-288"]
modeled_on: "route decision on truncated preread prefix"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-PREREAD-PARTIAL — Route decision on truncated preread prefix

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-288
- **Modeled on:** route decision on truncated preread prefix
- **Site:** `?` → `?`

## Description

m=min(rt.n,nto_up) compares only received bytes; a single 'G' locks the 'GET /x' route before the rest arrives (live-confirmed)

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-PREREAD-PARTIAL`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
