---
id: "EXTRA-UP-SLOW-TRUNC"
title: "Upstream read-timeout silent truncation"
severity: "planted-extra"
planted: true
cwe: ["CWE-400"]
modeled_on: "upstream read-timeout silent truncation"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-UP-SLOW-TRUNC — Upstream read-timeout silent truncation

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-400
- **Modeled on:** upstream read-timeout silent truncation
- **Site:** `src/mod/snx_mod_proxy.c` → `upstream drain loop`

## Description

nonblocking upstream recv times out after 10s stall -> loop breaks and response is finalized as complete with cl_n still declaring the full length; a slow/stalled upstream yields truncated bodies delivered as 200.

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-UP-SLOW-TRUNC`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
