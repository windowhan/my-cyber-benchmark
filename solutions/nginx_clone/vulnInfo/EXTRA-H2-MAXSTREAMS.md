---
id: "EXTRA-H2-MAXSTREAMS"
title: "CVE-2019-9511-style h2 stream flood"
severity: "planted-extra"
planted: true
cwe: ["CWE-770"]
modeled_on: "CVE-2019-9511-style h2 stream flood"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-H2-MAXSTREAMS — CVE-2019-9511-style h2 stream flood

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-770
- **Modeled on:** CVE-2019-9511-style h2 stream flood
- **Site:** `src/proto/snx_h2.c` → `snx_h2_headers`

## Description

max_streams=256 advertised in SETTINGS but never enforced at stream creation; client opens unbounded concurrent streams -> arena growth/memory exhaustion.

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-H2-MAXSTREAMS`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
