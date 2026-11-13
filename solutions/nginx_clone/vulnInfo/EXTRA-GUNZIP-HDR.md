---
id: "EXTRA-GUNZIP-HDR"
title: "Gunzip optional-header unbounded scan"
severity: "planted-extra"
planted: true
cwe: ["CWE-125"]
modeled_on: "gunzip optional-header unbounded scan"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-GUNZIP-HDR — Gunzip optional-header unbounded scan

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-125
- **Modeled on:** gunzip optional-header unbounded scan
- **Site:** `src/mod/snx_mod_gunzip.c` → `snx_gz_hdr_skip`

## Description

FNAME/FCOMMENT fields scanned for NUL with no bounds check; crafted .gz (FLG=0x18, no NUL) reads past the tight malloc(flen) body buf. ASan heap-buffer-overflow live-confirmed via /gunz/evil.txt + gzip_static always.

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-GUNZIP-HDR`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
