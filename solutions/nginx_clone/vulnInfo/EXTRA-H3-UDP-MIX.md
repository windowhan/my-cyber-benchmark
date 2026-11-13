---
id: "EXTRA-H3-UDP-MIX"
title: "QUIC session confusion across peers"
severity: "planted-extra"
planted: true
cwe: ["CWE-384"]
modeled_on: "QUIC session confusion across peers"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-H3-UDP-MIX — QUIC session confusion across peers

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-384
- **Modeled on:** QUIC session confusion across peers
- **Site:** `?` → `?`

## Description

one persistent conn per worker over the shared UDP socket; datagrams from different senders append into the same q->inbuf cumulative parse buffer, mixing peer state

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-H3-UDP-MIX`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
