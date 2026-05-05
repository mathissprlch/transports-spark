#!/usr/bin/env python3
"""4 concurrent BidiHello streams on one channel."""
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
        msgs = []
        for resp in stub.BidiHello(gen(), timeout=5):
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
    name_groups = [
        ['a1','a2'],
        ['b1','b2','b3'],
        ['c1'],
        ['d1','d2','d3','d4'],
    ]
    for i in range(N):
        t = threading.Thread(target=stream, args=(stub, name_groups[i], results, i))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    elapsed = time.time() - t0
    for i, r in enumerate(results):
        if isinstance(r, list):
            print(f'  [{i}] ({len(r)}) {", ".join(r)}')
        else:
            print(f'  [{i}] {r}')
    print(f'{N} concurrent bidi streams in {elapsed*1000:.0f}ms')

if __name__ == '__main__':
    main()
