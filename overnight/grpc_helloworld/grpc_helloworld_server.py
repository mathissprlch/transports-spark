#!/usr/bin/env python3
"""
Reference helloworld.Greeter gRPC server, used as the wire-compat
peer for the Ada v0.2 stack (greeter_client_v02). Listens on
:50051 by default with HTTP/2 prior knowledge (no TLS).

Run:
    python3 -m venv venv && source venv/bin/activate
    pip install grpcio grpcio-tools
    python3 -m grpc_tools.protoc -I../../crates/examples/proto \
        --python_out=. --grpc_python_out=. \
        ../../crates/examples/proto/helloworld.proto
    python3 grpc_helloworld_server.py

Then from the Ada side:
    cd crates/examples && alr run --skip-build -- greeter_client_v02
"""

import argparse
import sys
import time
from concurrent import futures
from datetime import datetime, timezone

import grpc

import helloworld_pb2
import helloworld_pb2_grpc


def log(msg, *, file=sys.stdout):
    ts = datetime.now(tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    print(f"[{ts}] {msg}", file=file, flush=True)


class Greeter(helloworld_pb2_grpc.GreeterServicer):
    def SayHello(self, request, context):
        log(f"SayHello name={request.name!r} from {context.peer()}")
        ua = next(
            (v for k, v in context.invocation_metadata() if k == "user-agent"),
            "?",
        )
        log(f"  user-agent: {ua}")
        return helloworld_pb2.HelloReply(message=f"Hello, {request.name}!")

    def LotsOfReplies(self, request, context):
        """Server-streaming: yield 5 replies for the one request."""
        log(f"LotsOfReplies name={request.name!r}")
        for i in range(1, 6):
            yield helloworld_pb2.HelloReply(message=f"Hello, {request.name}! [{i}/5]")

    def LotsOfGreetings(self, request_iterator, context):
        """Client-streaming: collect all names, return single combined reply."""
        names = []
        for req in request_iterator:
            log(f"LotsOfGreetings: got name={req.name!r}")
            names.append(req.name)
        joined = ", ".join(names) if names else "(none)"
        return helloworld_pb2.HelloReply(message=f"Hello to all: {joined}!")

    def BidiHello(self, request_iterator, context):
        """Bidi: for each request emit a reply (1:1 interleaved here)."""
        for req in request_iterator:
            log(f"BidiHello: got name={req.name!r}")
            yield helloworld_pb2.HelloReply(message=f"Hi, {req.name}!")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=50051)
    args = ap.parse_args()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    helloworld_pb2_grpc.add_GreeterServicer_to_server(Greeter(), server)
    bind = f"{args.host}:{args.port}"
    server.add_insecure_port(bind)
    server.start()
    log(f"helloworld.Greeter gRPC server on {bind}")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        log("shutting down")
        server.stop(grace=1).wait()


if __name__ == "__main__":
    main()
