---
id: "EXTRA-TLS-SNI-OVERFLOW"
title: "SNI server_name staged into a fixed routing buffer"
severity: "planted-extra"
planted: true
cwe: ["CWE-121"]
modeled_on: "SNI server_name staged into a fixed routing buffer"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-TLS-SNI-OVERFLOW — SNI server_name staged into a fixed routing buffer

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-121
- **Modeled on:** SNI server_name staged into a fixed routing buffer
- **Site:** `?` → `?`

## Description

char name[64]; ClientHello server_name up to 255 bytes overflows it; ASan-confirmed via openssl s_client -servername <200B>

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-TLS-SNI-OVERFLOW`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
