# nginx patched vulnerability information

Source: https://nginx.org/en/security_advisories.html (retrieved 2026-11-12). 68 entries — one file per advisory. CVSS from NVD.

| ID | Title | nginx sev | CVSS | Vulnerable | Fixed |
|---|---|---|---|---|---|
| [CVE-2026-15176](CVE-2026-15176.md) | Buffer overflow when using alias with rewrite | medium | 8.1 HIGH | 0.1.29-1.31.6 | 1.31.7+, 1.30.6+ |
| [CVE-2026-93479](CVE-2026-93479.md) | Buffer overflow in script evaluation | medium | 8.1 HIGH | 1.31.2-1.31.6, 1.30.0-1.30.5 | 1.31.7+, 1.30.6+ |
| [CVE-2026-95101](CVE-2026-95101.md) | Request body injection in HTTP/3 | medium | 5.3 MEDIUM | 1.25.0-1.31.6 | 1.31.7+, 1.30.6+ |
| [CVE-2026-97629](CVE-2026-97629.md) | Session forgery when using TLS session tickets | medium | 6.5 MEDIUM | 1.23.2-1.31.6 | 1.31.7+, 1.30.6+ |
| [CVE-2026-97205](CVE-2026-97205.md) | Use-after-free when using asynchronous file I/O (AIO) | medium | 8.1 HIGH | 0.8.11-1.31.6 | 1.31.7+, 1.30.6+ |
| [CVE-2026-90439](CVE-2026-90439.md) | Buffer overflow when using ngx_http_v3_module | medium | 6.5 MEDIUM | 1.29.2-1.31.5 | 1.31.6+, 1.30.5+ |
| [CVE-2026-42533](CVE-2026-42533.md) | Buffer overflow when using map and regex | major | 8.1 HIGH | 0.9.6-1.31.2 | 1.31.3+, 1.30.4+ |
| [CVE-2026-60005](CVE-2026-60005.md) | Memory disclosure when using ngx_http_slice_module | medium | 8.2 HIGH | 1.15.8-1.31.2 | 1.31.3+, 1.30.4+ |
| [CVE-2026-56434](CVE-2026-56434.md) | Use-after-free when using ngx_http_ssi_module | medium | 6.5 MEDIUM | 0.8.11-1.31.2 | 1.31.3+, 1.30.4+ |
| [CVE-2026-42530](CVE-2026-42530.md) | Use-after-free in HTTP/3 | major | 8.1 HIGH | 1.31.0-1.31.1 | 1.31.2+ |
| [CVE-2026-42055](CVE-2026-42055.md) | Buffer overflow in the ngx_http_proxy_v2_module and ngx_http_grpc_module | medium | 8.1 HIGH | 1.13.10-1.31.1 | 1.31.2+, 1.30.3+ |
| [CVE-2026-48142](CVE-2026-48142.md) | Buffer overread in the ngx_http_charset_module | low | 4.8 MEDIUM | 0.3.50-1.31.1 | 1.31.2+, 1.30.3+ |
| [CVE-2026-9256](CVE-2026-9256.md) | Buffer overflow in the ngx_http_rewrite_module | medium | 8.1 HIGH | 0.1.17-1.31.0 | 1.31.1+, 1.30.2+ |
| [CVE-2026-42926](CVE-2026-42926.md) | HTTP/2 request injection in the ngx_http_proxy_module | medium | 5.8 MEDIUM | 1.29.4-1.30.0 | 1.31.0+, 1.30.1+ |
| [CVE-2026-42945](CVE-2026-42945.md) | Buffer overflow in the ngx_http_rewrite_module | medium | 8.1 HIGH | 0.6.27-1.30.0 | 1.31.0+, 1.30.1+ |
| [CVE-2026-42946](CVE-2026-42946.md) | Buffer overread in the ngx_http_scgi_module and ngx_http_uwsgi_module | medium | 6.5 MEDIUM | 0.8.42-1.30.0 | 1.31.0+, 1.30.1+ |
| [CVE-2026-42934](CVE-2026-42934.md) | Buffer overread in the ngx_http_charset_module | low | 4.8 MEDIUM | 0.3.50-1.30.0 | 1.31.0+, 1.30.1+ |
| [CVE-2026-40460](CVE-2026-40460.md) | HTTP/3 address spoofing | medium | 6.5 MEDIUM | 1.25.0-1.30.0 | 1.31.0+, 1.30.1+ |
| [CVE-2026-40701](CVE-2026-40701.md) | resolver use-after-free in OCSP | medium | 4.8 MEDIUM | 1.19.0-1.30.0 | 1.31.0+, 1.30.1+ |
| [CVE-2026-27654](CVE-2026-27654.md) | Buffer overflow in ngx_http_dav_module | medium | 8.2 HIGH | 0.5.13-1.29.6 | 1.29.7+, 1.28.3+ |
| [CVE-2026-27784](CVE-2026-27784.md) | Buffer overflow in the ngx_http_mp4_module | medium | 7.8 HIGH | 1.1.19-1.29.6 | 1.29.7+, 1.28.3+ |
| [CVE-2026-32647](CVE-2026-32647.md) | Buffer overflow in the ngx_http_mp4_module | medium | 7.8 HIGH | 1.1.19-1.29.6 | 1.29.7+, 1.28.3+ |
| [CVE-2026-27651](CVE-2026-27651.md) | NULL pointer dereference while using CRAM-MD5 or APOP | low | 7.5 HIGH | 0.5.15-1.29.6 | 1.29.7+, 1.28.3+ |
| [CVE-2026-28753](CVE-2026-28753.md) | Injection in auth_http and XCLIENT | medium | 3.7 LOW | 0.6.27-1.29.6 | 1.29.7+, 1.28.3+ |
| [CVE-2026-28755](CVE-2026-28755.md) | OCSP result bypass in stream | medium | 5.4 MEDIUM | 1.27.2-1.29.6 | 1.29.7+, 1.28.3+ |
| [CVE-2026-1642](CVE-2026-1642.md) | SSL upstream injection | medium | 5.9 MEDIUM | 1.3.0-1.29.4 | 1.29.5+, 1.28.2+ |
| [CVE-2025-53859](CVE-2025-53859.md) | Buffer overread in the ngx_mail_smtp_module | low | 3.7 LOW | 0.7.22-1.29.0 | 1.29.1+ |
| [CVE-2025-23419](CVE-2025-23419.md) | SSL session reuse vulnerability | medium | 4.3 MEDIUM | 1.11.4-1.27.3 | 1.27.4+, 1.26.3+ |
| [CVE-2024-7347](CVE-2024-7347.md) | Buffer overread in the ngx_http_mp4_module | low | 4.7 MEDIUM | 1.5.13-1.27.0 | 1.27.1+, 1.26.2+ |
| [CVE-2024-32760](CVE-2024-32760.md) | Buffer overwrite in HTTP/3 | medium | 6.5 MEDIUM | 1.25.0-1.25.5, 1.26.0 | 1.27.0+, 1.26.1+ |
| [CVE-2024-31079](CVE-2024-31079.md) | Stack overflow and use-after-free in HTTP/3 | medium | 4.8 MEDIUM | 1.25.0-1.25.5, 1.26.0 | 1.27.0+, 1.26.1+ |
| [CVE-2024-35200](CVE-2024-35200.md) | NULL pointer dereference in HTTP/3 | medium | 5.3 MEDIUM | 1.25.0-1.25.5, 1.26.0 | 1.27.0+, 1.26.1+ |
| [CVE-2024-34161](CVE-2024-34161.md) | Memory disclosure in HTTP/3 | medium | 5.3 MEDIUM | 1.25.0-1.25.5, 1.26.0 | 1.27.0+, 1.26.1+ |
| [CVE-2024-24989](CVE-2024-24989.md) | NULL pointer dereference in HTTP/3 | major | 7.5 HIGH | 1.25.3 | 1.25.4+ |
| [CVE-2024-24990](CVE-2024-24990.md) | Use-after-free in HTTP/3 | major | 7.5 HIGH | 1.25.0-1.25.3 | 1.25.4+ |
| [CVE-2022-41741](CVE-2022-41741.md) | Memory corruption in the ngx_http_mp4_module | medium | 7.0 HIGH | 1.1.3-1.23.1, 1.0.7-1.0.15 | 1.23.2+, 1.22.1+ |
| [CVE-2022-41742](CVE-2022-41742.md) | Memory disclosure in the ngx_http_mp4_module | medium | 7.1 HIGH | 1.1.3-1.23.1, 1.0.7-1.0.15 | 1.23.2+, 1.22.1+ |
| [CVE-2021-23017](CVE-2021-23017.md) | 1-byte memory overwrite in resolver | medium | 7.7 HIGH | 0.6.18-1.20.0 | 1.21.0+, 1.20.1+ |
| [CVE-2019-9511](CVE-2019-9511.md) | Excessive CPU usage in HTTP/2 with small window updates | medium | 7.5 HIGH | 1.9.5-1.17.2 | 1.17.3+, 1.16.1+ |
| [CVE-2019-9513](CVE-2019-9513.md) | Excessive CPU usage in HTTP/2 with priority changes | low | 7.5 HIGH | 1.9.5-1.17.2 | 1.17.3+, 1.16.1+ |
| [CVE-2019-9516](CVE-2019-9516.md) | Excessive memory usage in HTTP/2 with zero length headers | low | 6.5 MEDIUM | 1.9.5-1.17.2 | 1.17.3+, 1.16.1+ |
| [CVE-2018-16843](CVE-2018-16843.md) | Excessive memory usage in HTTP/2 | low | 7.5 HIGH | 1.9.5-1.15.5 | 1.15.6+, 1.14.1+ |
| [CVE-2018-16844](CVE-2018-16844.md) | Excessive CPU usage in HTTP/2 | low | 7.5 HIGH | 1.9.5-1.15.5 | 1.15.6+, 1.14.1+ |
| [CVE-2018-16845](CVE-2018-16845.md) | Memory disclosure in the ngx_http_mp4_module | medium | 6.1 MEDIUM | 1.1.3-1.15.5, 1.0.7-1.0.15 | 1.15.6+, 1.14.1+ |
| [CVE-2017-7529](CVE-2017-7529.md) | Integer overflow in the range filter | medium | 7.5 HIGH | 0.5.6-1.13.2 | 1.13.3+, 1.12.1+ |
| [CVE-2016-4450](CVE-2016-4450.md) | NULL pointer dereference while writing client request body | medium | 7.5 HIGH | 1.3.9-1.11.0 | 1.11.1+, 1.10.1+ |
| [CVE-2016-0742](CVE-2016-0742.md) | Invalid pointer dereference in resolver | medium | 7.5 HIGH | 0.6.18-1.9.9 | 1.9.10+, 1.8.1+ |
| [CVE-2016-0746](CVE-2016-0746.md) | Use-after-free during CNAME response processing in resolver | medium | 9.8 CRITICAL | 0.6.18-1.9.9 | 1.9.10+, 1.8.1+ |
| [CVE-2016-0747](CVE-2016-0747.md) | Insufficient limits of CNAME resolution in resolver | medium | 5.3 MEDIUM | 0.6.18-1.9.9 | 1.9.10+, 1.8.1+ |
| [CVE-2014-3616](CVE-2014-3616.md) | SSL session reuse vulnerability | medium | 4.3 MEDIUM | 0.5.6-1.7.4 | 1.7.5+, 1.6.2+ |
| [CVE-2014-3556](CVE-2014-3556.md) | STARTTLS command injection | medium | 6.8 MEDIUM | 1.5.6-1.7.3 | 1.7.4+, 1.6.1+ |
| [CVE-2014-0133](CVE-2014-0133.md) | SPDY heap buffer overflow | major | 7.5 HIGH | 1.3.15-1.5.11 | 1.5.12+, 1.4.7+ |
| [CVE-2014-0088](CVE-2014-0088.md) | SPDY memory corruption | major | 7.5 HIGH | 1.5.10 | 1.5.11+ |
| [CVE-2013-4547](CVE-2013-4547.md) | Request line parsing vulnerability | medium | 7.5 HIGH | 0.8.41-1.5.6 | 1.5.7+, 1.4.4+ |
| [CVE-2013-2070](CVE-2013-2070.md) | Memory disclosure with specially crafted HTTP backend responses | medium | 5.8 MEDIUM | 1.1.4-1.2.8, 1.3.9-1.4.0 | 1.5.0+, 1.4.1+, 1.2.9+ |
| [CVE-2013-2028](CVE-2013-2028.md) | Stack-based buffer overflow with specially crafted request | major | 7.5 HIGH | 1.3.9-1.4.0 | 1.5.0+, 1.4.1+ |
| [CVE-2011-4963](CVE-2011-4963.md) | Vulnerabilities with Windows directory aliases | medium | 5.0 MEDIUM | nginx/Windows 0.7.52-1.3.0 | 1.3.1+, 1.2.1+ |
| [CVE-2012-2089](CVE-2012-2089.md) | Buffer overflow in the ngx_http_mp4_module | major | 6.8 MEDIUM | 1.1.3-1.1.18, 1.0.7-1.0.14 | 1.1.19+, 1.0.15+ |
| [CVE-2012-1180](CVE-2012-1180.md) | Memory disclosure with specially crafted backend responses | major | 5.0 MEDIUM | 0.1.0-1.1.16 | 1.1.17+, 1.0.14+ |
| [CVE-2011-4315](CVE-2011-4315.md) | Buffer overflow in resolver | medium | 6.8 MEDIUM | 0.6.18-1.1.7 | 1.1.8+, 1.0.10+ |
| [CVE-2010-2266](CVE-2010-2266.md) | Vulnerabilities with invalid UTF-8 sequence on Windows | major | 5.0 MEDIUM | nginx/Windows 0.7.52-0.8.40 | 0.8.41+, 0.7.67+ |
| [CVE-2010-2263](CVE-2010-2263.md) | Vulnerabilities with Windows file default stream | major | 5.0 MEDIUM | nginx/Windows 0.7.52-0.8.39 | 0.8.40+, 0.7.66+ |
| [CORE-2010-0121](CORE-2010-0121.md) | Vulnerabilities with Windows 8.3 filename pseudonyms | major | n/a | nginx/Windows 0.7.52-0.8.32 | 0.8.33+, 0.7.65+ |
| [CVE-2009-4487](CVE-2009-4487.md) | An error log data are not sanitized | none | 6.8 MEDIUM | all | none |
| [CVE-2009-3555](CVE-2009-3555.md) | The renegotiation vulnerability in SSL protocol | major | 9.8 CRITICAL | 0.1.0-0.8.22 | 0.8.23+, 0.7.64+ |
| [CVE-2009-3898](CVE-2009-3898.md) | Directory traversal vulnerability | minor | 4.9 MEDIUM | 0.1.0-0.8.16 | 0.8.17+, 0.7.63+ |
| [CVE-2009-2629](CVE-2009-2629.md) | Buffer underflow vulnerability | major | 7.5 HIGH | 0.1.0-0.8.14 | 0.8.15+, 0.7.62+, 0.6.39+, 0.5.38+ |
| [CVE-2009-3896](CVE-2009-3896.md) | Null pointer dereference vulnerability | major | 5.0 MEDIUM | 0.1.0-0.8.13 | 0.8.14+, 0.7.62+, 0.6.39+, 0.5.38+ |
