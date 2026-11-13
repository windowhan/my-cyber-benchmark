---
id: "EXTRA-OFC-COLLISION"
title: "File confusion via truncated cache keys (open_file_cache class)"
severity: "planted-extra"
planted: true
cwe: ["CWE-436"]
modeled_on: "file confusion via truncated cache keys (open_file_cache class)"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-OFC-COLLISION — File confusion via truncated cache keys (open_file_cache class)

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-436
- **Modeled on:** file confusion via truncated cache keys (open_file_cache class)
- **Site:** `?` → `?`

## Description

snx_ofc_tbl keys are path[256] via snprintf truncation; two distinct paths sharing a 255-byte prefix collide and the first entry's fd is dup()ed to the second requester

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-OFC-COLLISION`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
