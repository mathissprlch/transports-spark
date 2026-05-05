#!/usr/bin/env python3
"""4 concurrent LotsOfGreetings streams on one channel."""
import sys, time, threading
import os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import grpc
import helloworld_pb2 as pb
import helloworld_pb2_grpc as pb_grpc

ADDR = 'localhost:50051'
N = 4

def stream(stub, names, results, idx):
    try:
        def gen():
            for n in names:
                yield pb.HelloRequest(name=n)
        resp = stub.LotsOfGreetings(gen(), timeout=5)
        results[idx] = resp.message
    except Exception as e:
        results[idx] = f'ERR: {e}'

def main():
    ch = grpc.insecure_channel(ADDR)
    stub = pb_grpc.GreeterStub(ch)
    results = [None] * N
    threads = []
    t0 = time.time()
    name_groups = [
        ['a1','a2','a3'],
        ['b1','b2'],
        ['c1','c2','c3','c4'],
        ['d1','d2','d3'],
    ]
    for i in range(N):
        t = threading.Thread(target=stream, args=(stub, name_groups[i], results, i))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    elapsed = time.time() - t0
    for i, r in enumerate(results):
        print(f'  [{i}] {r}')
    print(f'{N} concurrent client-streams in {elapsed*1000:.0f}ms')

if __name__ == '__main__':
    main()
