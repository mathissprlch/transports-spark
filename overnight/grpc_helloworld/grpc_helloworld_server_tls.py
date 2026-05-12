#!/usr/bin/env python3
"""TLS-enabled gRPC helloworld server for the grpc_tls_demo."""

import argparse
import sys
import time
from concurrent import futures
import grpc

import helloworld_pb2
import helloworld_pb2_grpc


class Greeter(helloworld_pb2_grpc.GreeterServicer):
    def SayHello(self, request, context):
        name_len = len(request.name)
        print(f"[grpc-tls-server] SayHello: name={name_len}B from {context.peer()}")
        reply = f"Hello over TLS, {request.name[:60]}... ({name_len}B name)"
        return helloworld_pb2.HelloReply(message=reply)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=50443)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    args = ap.parse_args()

    with open(args.key, "rb") as f:
        key_pem = f.read()
    with open(args.cert, "rb") as f:
        cert_pem = f.read()

    creds = grpc.ssl_server_credentials([(key_pem, cert_pem)])
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    helloworld_pb2_grpc.add_GreeterServicer_to_server(Greeter(), server)
    server.add_secure_port(f"0.0.0.0:{args.port}", creds)
    server.start()
    print(f"[grpc-tls-server] listening on :{args.port} with TLS")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        server.stop(grace=1).wait()


if __name__ == "__main__":
    main()
