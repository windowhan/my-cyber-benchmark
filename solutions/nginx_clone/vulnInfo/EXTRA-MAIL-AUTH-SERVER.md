---
id: "EXTRA-MAIL-AUTH-SERVER"
title: "Auth_http reply injection"
severity: "planted-extra"
planted: true
cwe: ["CWE-120"]
modeled_on: "auth_http reply injection"
source: "ground_truth.json (benchmark insert)"
---
# EXTRA-MAIL-AUTH-SERVER — Auth_http reply injection

- **Type:** planted benchmark weakness (extra, not a canonical nginx CVE)
- **CWE:** CWE-120
- **Modeled on:** auth_http reply injection
- **Site:** `src/snx_mail.c` → `snx_mail_auth_http`

## Description

Auth-Server value memcpy into malloc(64) unbounded -> heap overflow via hostile auth responder. Live: long Auth-Server to :8025.

## Verification

Live trigger is in `poc/http/live.sh` (run `bash poc/http/live.sh EXTRA-MAIL-AUTH-SERVER`); check `logs/` and ASan output for the crash/evidence. Unit-style harnesses live under `poc/unit/`.
