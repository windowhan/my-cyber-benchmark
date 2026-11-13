---
id: "EXTRA-TLS-SESSION-CTX"
title: "Session id context shared across vhosts"
severity: "planted-extra"
planted: true
cwe: ["CWE-384"]
modeled_on: "session id context shared across vhosts"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-TLS-SESSION-CTX — Session id context shared across vhosts

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-384
- **Modeled on:** session id context shared across vhosts
- **Site:** `?` → `?`

## Description

constant 'snx' id context for every server ctx; a session issued under one cert can resume under another vhost's ctx after SNI switch

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-TLS-SESSION-CTX`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
