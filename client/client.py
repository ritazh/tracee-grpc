"""The Python implementation of the gRPC tracee client."""

from __future__ import print_function

import random
import logging

import grpc

import tracee_pb2
import tracee_pb2_grpc


def generate_trace(event):
    trace = tracee_pb2.Trace(
        event= "%d" % event
    )
    yield trace

def record_trace(stub, event):
    tracee_iterator = generate_trace(event)
    tracee_result = stub.RecordTrace(tracee_iterator)
    print("returned result: %s" % tracee_result)

def run():
    with grpc.insecure_channel('localhost:10000') as channel:
        stub = tracee_pb2_grpc.TraceeStub(channel)
        print("-------------- RecordTrace --------------")
        for i in range(0, 10):
            print("index: %d" % i)
            event = random.randint(0,5)
            print("event: %d" % event)
            if event %2 == 0:
                print("record")
                record_trace(stub, event)

if __name__ == '__main__':
    logging.basicConfig()
    run()
