---
id: "EXTRA-MEMCACHED-INJ"
title: "Ascii-protocol key injection"
severity: "planted-extra"
planted: true
cwe: ["['CWE-77']"]
modeled_on: "ascii-protocol key injection"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-MEMCACHED-INJ — Ascii-protocol key injection

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** ['CWE-77']
- **Modeled on:** ascii-protocol key injection
- **Site:** `src/mod/snx_mod_upstream.c` → `?`

## Description

new-feature module

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-MEMCACHED-INJ`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
