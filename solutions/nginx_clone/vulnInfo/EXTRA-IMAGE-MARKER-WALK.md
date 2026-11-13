---
id: "EXTRA-IMAGE-MARKER-WALK"
title: "Jpeg marker parse"
severity: "planted-extra"
planted: true
cwe: ["CWE-125"]
modeled_on: "jpeg marker parse"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-IMAGE-MARKER-WALK — Jpeg marker parse

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-125
- **Modeled on:** jpeg marker parse
- **Site:** `src/mod/snx_mod_image.c` → `snx_jpeg_dims`

## Description

p += 1+seg trusts file seg length; bailout allows p < end+64 -> OOB read past buffer. Live: /img/evil.jpg -> ASan heap-buffer-overflow.

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-IMAGE-MARKER-WALK`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
