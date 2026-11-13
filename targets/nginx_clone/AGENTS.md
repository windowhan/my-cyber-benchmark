# snx — vulnerability-assessment benchmark web server

> ## DO NOT PATCH THE VULNERABILITIES
>
> This repository intentionally contains deliberately planted memory-safety
> and logic vulnerabilities modeled on real nginx CVEs. They are the product:
> the codebase is a **benchmark test dataset** for vulnerability-assessment
> tooling (scanners, fuzzers, AI code-review evaluation).
>
> - The canonical 68 vulnerabilities are mapped in `ground_truth.json`.
> - Additional modeled weaknesses are tracked separately under the
>   `extras` array in the same file.
> - Crashes, ASan/UBSan reports, hangs, and insecure behavior in this code
>   are **expected** — the PoC suite asserts they fire.
> - Do not "fix" suspicious-looking code (unchecked lengths, missing NULL
>   checks, truncation, races, weak parsing) without confirming against
>   `ground_truth.json` first. Two canonical entries were once accidentally
>   repaired as "bugs" and had to be re-broken to keep the benchmark intact.
> - New features should still plant modeled weaknesses where a real nginx
>   module would plausibly have them, and be recorded in `extras`.

## Layout

- `src/` — independent C implementation (`snx_` symbols; NOT nginx code):
  arena alloc, chained iobufs, conf-node tree, step-dispatch http pipeline,
  kqueue event loop, TLS (OpenSSL), h2/spdy/h3-quic, mail, stream.
- `conf/snx.conf` — test config: http 8080, h2c 8081, https 8443,
  quic/udp 8444, smtp 8025, imap 8143, pop3 8110, stream 9000/9001.
- `poc/unit/` — unit PoC harnesses (4 bins, 35 CVE triggers).
- `poc/http/live.sh` — live wire PoCs (29 CVE + feature/extra cases).
- `poc/fuzz/` — libFuzzer harness (request line, headers, unescape,
  HPACK, JWT).
- `ground_truth.json` — vulnerability ↔ source mapping (`vulnerabilities`
  = canonical 68, `extras` = additional modeled weaknesses).

## Build

```sh
make                 # normal binary: ./snx
make snx_asan CC=/opt/homebrew/opt/llvm/bin/clang
                     # ASan+UBSan binary (Homebrew llvm REQUIRED — the
                     #  .asan.o objects must match the fuzz/unit ABI;
                     #  Apple CLT clang lacks the fuzzer runtime)
./snx_asan -t -c conf/snx.conf     # config test
./snx_asan -g -c conf/snx.conf     # foreground run (dev cert: conf/dev.*)
```

## Verify

```sh
bash poc/run_all.sh unit      # unit PoCs: expect 35/35 triggered
bash poc/http/live.sh         # live wire PoCs: expect all PASS
                              # (a stuck backend.py holds the pipe —
                              #  pkill -f backend.py to flush output)
cd poc/fuzz && make && make corpus
./fuzz_snx corpus -max_total_time=30
```

Pass = the planted bugs still fire. A PASS count drop means a vulnerability
was accidentally patched — restore it.

## Conventions

- C (kqueue/macOS, OpenSSL), independent design — do not introduce nginx
  symbols, layout, or copied implementation.
- Keep diffs focused; preserve existing comments.
- Never commit real secrets; `conf/dev.crt`/`dev2.crt` are throwaway dev
  certs for local TLS tests only.
