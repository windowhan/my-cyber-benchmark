---
id: "EXTRA-ZONE-KEY"
title: "Shared-zone key buffer overflow"
severity: "planted-extra"
planted: true
cwe: ["CWE-787"]
modeled_on: "shared-zone key buffer overflow"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-ZONE-KEY — Shared-zone key buffer overflow

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-787
- **Modeled on:** shared-zone key buffer overflow
- **Site:** `?` → `?`

## Description

zone entry key is uchar[128] but memcpy uses unbounded key->n; long keys (e.g. $uri-based limit keys) overflow the shared-mem entry

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-ZONE-KEY`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
