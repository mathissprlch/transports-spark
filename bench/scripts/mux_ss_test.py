#!/usr/bin/env python3
"""4 concurrent LotsOfReplies streams on one channel."""
import sys, time, threading
import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import grpc
import helloworld_pb2 as pb
import helloworld_pb2_grpc as pb_grpc

ADDR = 'localhost:50051'
N = 4

def stream(stub, name, results, idx):
    try:
        msgs = []
        for resp in stub.LotsOfReplies(pb.HelloRequest(name=name), timeout=5):
            msgs.append(resp.message)
        results[idx] = msgs
    except Exception as e:
        results[idx] = f'ERR: {e}'

def main():
    ch = grpc.insecure_channel(ADDR)
    stub = pb_grpc.GreeterStub(ch)
    results = [None] * N
    threads = []
    t0 = time.time()
    for i in range(N):
        t = threading.Thread(target=stream, args=(stub, f'caller{i}', results, i))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    elapsed = time.time() - t0
    for i, r in enumerate(results):
        if isinstance(r, list):
            print(f'  [{i}] {len(r)} replies: {r[0]} ... {r[-1]}')
        else:
            print(f'  [{i}] {r}')
    print(f'{N} concurrent server-streams in {elapsed*1000:.0f}ms')

if __name__ == '__main__':
    main()
