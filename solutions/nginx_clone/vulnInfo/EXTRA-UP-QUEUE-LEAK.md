---
id: "EXTRA-UP-QUEUE-LEAK"
title: "Queue accounting leak"
severity: "planted-extra"
planted: true
cwe: ["CWE-667"]
modeled_on: "queue accounting leak"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-UP-QUEUE-LEAK — Queue accounting leak

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-667
- **Modeled on:** queue accounting leak
- **Site:** `src/mod/snx_mod_upstream.c` → `snx_upstream_pick`

## Description

conns++ claimed before queue wait; on timeout returns NULL without releasing -> peer saturates permanently -> DoS.

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-UP-QUEUE-LEAK`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
