#!/usr/bin/env python3
"""fake upstream on :9100 - captures the forwarded request, replies
with a large body so partial-send paths can escape."""
import socket, sys, threading

def serve():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 9100))
    s.listen(4)
    while True:
        c, _ = s.accept()
        def handle(c):
            req = b""
            c.settimeout(3)
            try:
                while b"\r\n\r\n" not in req:
                    d = c.recv(4096)
                    if not d:
                        break
                    req += d
            except socket.timeout:
                pass
            open("/tmp/snx_upstream_req.bin", "wb").write(req)
            body = b"B" * (256 * 1024)
            resp = (b"HTTP/1.1 200 OK\r\nContent-Length: " +
                    str(len(body)).encode() + b"\r\n\r\n" + body)
            try:
                c.sendall(resp)
            except OSError:
                pass
            c.close()
        threading.Thread(target=handle, args=(c,), daemon=True).start()

serve()
