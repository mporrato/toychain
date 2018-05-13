#!/usr/bin/env python3

from datetime import datetime
from hashlib import sha256


class Block:

    def __init__(self, idx, prev, payload):
        self._idx = idx
        self._prev = prev
        self._payload = payload.encode()
        self._timestamp = 0
        self._nonce = 0

    @property
    def idx(self):
        return self._idx

    @property
    def prev(self):
        return self._prev

    @property
    def payload(self):
        return self._payload

    def hash(self):
        # TODO: This can be optimised by caching the partial hash
        # of the properties excluding timestamp and nonce
        body = self._idx.to_bytes(8, byteorder='big')
        body += self._payload
        body += self._timestamp.to_bytes(4, byteorder='big')
        body += self._nonce.to_bytes(4, byteorder='big')
        return sha256(body).digest()

    def mine(self, target):
        while True:
            self._timestamp = int(datetime.utcnow().timestamp())
            for self._nonce in range(1 << 32):
                if int.from_bytes(self.hash(), byteorder='big') < target:
                    return

    def validate(self, hash):
        return self.hash() == hash

    def __str__(self):
        fmt = 'Block(idx={}, prev={}, payload={}, time={}, nonce={}, hash={})'
        return fmt.format(
            self._idx, self._prev.hex(), self._payload,
            datetime.fromtimestamp(self._timestamp),
            self._nonce, self.hash().hex()
        )


class Chain:

    def __init__(self):
        self._blocks = {}
        self._tail = None

    def get(self, h):
        return self._blocks.get(h)

    @property
    def tail(self):
        return self.get(self._tail)

    def walk(self):
        prev = self.tail
        while prev is not None:
            yield prev
            prev = self.get(prev.prev)

    def validate(self):
        idx = None
        expected_hash = self._tail
        for block in self.walk():
            if idx is not None:
                if block.idx != idx - 1:
                    return False
            if not block.validate(expected_hash):
                return False
            idx = block.idx
            expected_hash = block.prev
        return True

    def append(self, payload, target):
        if self._tail is None:
            # Genesis block
            block = Block(0, (0).to_bytes(32, byteorder='big'), payload)
        else:
            block = Block(self.tail.idx + 1, self.tail.hash(), payload)
        block.mine(target)
        self._tail = block.hash()
        self._blocks[self._tail] = block


if __name__ == '__main__':
    target = 1 << 235
    c = Chain()
    payloads = [
        'This is the genesis block',
        'Hello, world!',
        'foo',
        'bar'
    ]
    for payload in payloads:
        c.append(payload, target)
        print(c.tail)
