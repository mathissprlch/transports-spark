#!/usr/bin/env python3
"""Concurrent SayHello calls to verify Ada mux server demuxes streams."""
import sys, time, threading
import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import grpc
import helloworld_pb2 as pb
import helloworld_pb2_grpc as pb_grpc

ADDR = 'localhost:50051'
N = 8

def call(stub, name, results, idx):
    try:
        resp = stub.SayHello(pb.HelloRequest(name=name), timeout=5)
        results[idx] = resp.message
    except Exception as e:
        results[idx] = f'ERR: {e}'

def main():
    ch = grpc.insecure_channel(ADDR)
    stub = pb_grpc.GreeterStub(ch)
    results = [None] * N
    threads = []
    t0 = time.time()
    for i in range(N):
        t = threading.Thread(target=call, args=(stub, f'caller{i}', results, i))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    elapsed = time.time() - t0
    for i, r in enumerate(results):
        print(f'  [{i}] {r}')
    print(f'{N} concurrent calls in {elapsed*1000:.0f}ms')

if __name__ == '__main__':
    main()
