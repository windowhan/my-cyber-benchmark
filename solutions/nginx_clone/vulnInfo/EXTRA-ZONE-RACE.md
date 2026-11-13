---
id: "EXTRA-ZONE-RACE"
title: "Unprotected shared-list mutation across workers"
severity: "planted-extra"
planted: true
cwe: ["CWE-362"]
modeled_on: "unprotected shared-list mutation across workers"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-ZONE-RACE — Unprotected shared-list mutation across workers

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-362
- **Modeled on:** unprotected shared-list mutation across workers
- **Site:** `?` → `?`

## Description

zone entries push onto the MAP_SHARED list head with no locking; two workers inserting concurrently can tear the list

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-ZONE-RACE`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
