#!/usr/bin/env python3
"""
Tiny prior-knowledge HTTP/2 echo server for fuzzing/soak-testing
the Ada http2_core.Connection driver.

Each request: respond with HEADERS(:status=200, content-type=text/plain)
then DATA(echo of request body) then HEADERS(grpc-status=0) trailing
empty-body END_STREAM.

Listens on 127.0.0.1:8080 by default. Exits on SIGTERM.

Uses python-h2 (hyper-h2): https://python-hyper.org/projects/h2/
"""

import argparse
import errno
import socket
import sys
import threading
import time
from datetime import datetime, timezone

import h2.config
import h2.connection
import h2.events


def log(msg, *, file=sys.stdout):
    ts = datetime.now(tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    print(f"[{ts}] {msg}", file=file, flush=True)


def serve_one(conn_sock, addr, request_count, lock):
    """Serve a single TCP connection. Returns when peer closes."""
    config = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
    h2c = h2.connection.H2Connection(config=config)
    h2c.initiate_connection()
    conn_sock.sendall(h2c.data_to_send())

    pending_streams = {}  # stream_id -> (request_headers, body_chunks)

    while True:
        try:
            data = conn_sock.recv(65535)
        except (ConnectionResetError, OSError) as e:
            log(f"recv error from {addr}: {e}")
            break
        if not data:
            break
        try:
            events = h2c.receive_data(data)
        except Exception as e:
            log(f"h2 receive_data error from {addr}: {type(e).__name__}: {e}")
            break

        for ev in events:
            if isinstance(ev, h2.events.RequestReceived):
                pending_streams[ev.stream_id] = (dict(ev.headers), bytearray())
            elif isinstance(ev, h2.events.DataReceived):
                if ev.stream_id in pending_streams:
                    pending_streams[ev.stream_id][1].extend(ev.data)
                h2c.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
            elif isinstance(ev, h2.events.StreamEnded):
                hdrs, body = pending_streams.pop(ev.stream_id, ({}, b""))
                with lock:
                    request_count[0] += 1
                    n = request_count[0]
                if n % 100 == 0:
                    log(f"#{n} stream={ev.stream_id} path={hdrs.get(':path', '?')} body={len(body)}B")
                resp_headers = [
                    (":status", "200"),
                    ("content-type", hdrs.get("content-type", "text/plain")),
                    ("server", "h2-echo-py"),
                ]
                h2c.send_headers(ev.stream_id, resp_headers)
                if body:
                    # Send body in one DATA frame (echo).
                    h2c.send_data(ev.stream_id, bytes(body), end_stream=False)
                # Trailing HEADERS to mimic gRPC trailers.
                h2c.send_headers(
                    ev.stream_id,
                    [("grpc-status", "0"), ("grpc-message", "ok")],
                    end_stream=True,
                )
            elif isinstance(ev, h2.events.ConnectionTerminated):
                log(f"peer GOAWAY: {ev}")
                break

        out = h2c.data_to_send()
        if out:
            try:
                conn_sock.sendall(out)
            except (ConnectionResetError, BrokenPipeError, OSError) as e:
                log(f"sendall error to {addr}: {e}")
                break

    try:
        conn_sock.close()
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    request_count = [0]
    lock = threading.Lock()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(64)
    log(f"h2_echo_server listening on {args.host}:{args.port}")

    try:
        while True:
            try:
                conn_sock, addr = sock.accept()
            except KeyboardInterrupt:
                break
            t = threading.Thread(
                target=serve_one,
                args=(conn_sock, addr, request_count, lock),
                daemon=True,
            )
            t.start()
    finally:
        log(f"final request count: {request_count[0]}")
        sock.close()


if __name__ == "__main__":
    main()
