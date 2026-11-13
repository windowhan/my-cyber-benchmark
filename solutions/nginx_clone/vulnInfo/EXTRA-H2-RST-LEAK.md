---
id: "EXTRA-H2-RST-LEAK"
title: "H2 rapid-reset stream accounting"
severity: "planted-extra"
planted: true
cwe: ["CWE-772"]
modeled_on: "h2 rapid-reset stream accounting"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-H2-RST-LEAK — H2 rapid-reset stream accounting

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-772
- **Modeled on:** h2 rapid-reset stream accounting
- **Site:** `src/proto/snx_h2.c` → `RST_STREAM dispatch`

## Description

closed streams are marked CLOSED but never unlinked; a rapid-reset flood keeps every stream+hdr_block in the conn list until teardown -> memory DoS.

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-H2-RST-LEAK`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
