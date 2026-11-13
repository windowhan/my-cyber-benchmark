---
id: "EXTRA-CACHE-TRAVERSAL"
title: "Cache key -> file path trust (nginx misc-cache class)"
severity: "planted-extra"
planted: true
cwe: ["['CWE-22']"]
modeled_on: "cache key -> file path trust (nginx misc-cache class)"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-CACHE-TRAVERSAL — Cache key -> file path trust (nginx misc-cache class)

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** ['CWE-22']
- **Modeled on:** cache key -> file path trust (nginx misc-cache class)
- **Site:** `src/mod/snx_mod_cache.c` → `?`

## Description

new-feature module

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-CACHE-TRAVERSAL`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
