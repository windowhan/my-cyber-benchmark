---
id: "EXTRA-IFRANGE-VALIDATOR"
title: "Weak validator acceptance in conditional range handling"
severity: "planted-extra"
planted: true
cwe: ["CWE-345"]
modeled_on: "weak validator acceptance in conditional range handling"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-IFRANGE-VALIDATOR — Weak validator acceptance in conditional range handling

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-345
- **Modeled on:** weak validator acceptance in conditional range handling
- **Site:** `?` → `?`

## Description

If-Range is only compared when r->etag.n != 0; a request with If-Range against an etag-less response still gets partial content even though the validator cannot match

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-IFRANGE-VALIDATOR`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
