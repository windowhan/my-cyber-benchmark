#!/usr/bin/env python3
"""raw HTTP request helper - sends bytes verbatim, prints response.
usage: req.py [--timeout S]  (request bytes on stdin)"""
import socket, sys

def main():
    timeout = 4
    argv = sys.argv[1:]
    if argv and argv[0] == "--timeout":
        timeout = float(argv[1])
    raw = sys.stdin.buffer.read()
    s = socket.create_connection(("127.0.0.1", 8080), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(raw)
        out = b""
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                out += d
        except socket.timeout:
            pass
        sys.stdout.buffer.write(out)
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        s.close()

main()
