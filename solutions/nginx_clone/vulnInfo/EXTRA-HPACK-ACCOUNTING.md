---
id: "EXTRA-HPACK-ACCOUNTING"
title: "CVE-2022-41741/41742-class h2 memory exhaustion"
severity: "planted-extra"
planted: true
cwe: ["CWE-400"]
modeled_on: "CVE-2022-41741/41742-class h2 memory exhaustion"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-HPACK-ACCOUNTING — CVE-2022-41741/41742-class h2 memory exhaustion

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-400
- **Modeled on:** CVE-2022-41741/41742-class h2 memory exhaustion
- **Site:** `?` → `?`

## Description

dynamic-table entry size counts name+value only; RFC 7541 4.1 requires +32 bytes per entry, so the table exceeds SETTINGS capacity ~25% before eviction

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-HPACK-ACCOUNTING`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
