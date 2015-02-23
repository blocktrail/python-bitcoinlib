# Copyright (C) 2013-2015 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from __future__ import absolute_import, division, print_function, unicode_literals

import unittest

from bitcoin.wallet import CKey, CBitcoinSecret
from bitcoin.core.key import CPubKey
from bitcoin.core.serialize import ImmutableSerializable
from bitcoin.wallet import P2PKHBitcoinAddress
import bitcoin
import base64
import sys
import os
import json

_bchr = chr
_bord = ord
if sys.version > '3':
    long = int
    _bchr = lambda x: bytes([x])
    _bord = lambda x: x

def load_test_vectors(name):
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        return json.load(fd)


def VerifyMessage(address, message, sig):
    sig = base64.b64decode(sig)
    hash = message.GetHash()

    pubkey = CPubKey.recover_compact(hash, sig)

    return str(P2PKHBitcoinAddress.from_pubkey(pubkey)) == address


def SignMessage(key, message):
    sig, i = key.sign_compact(message.GetHash())

    meta = 27 + i
    if key.is_compressed:
        meta += 4

    return base64.b64encode(_bchr(meta) + sig)


class BitcoinMessage(ImmutableSerializable):
    __slots__ = ['magic', 'message']

    def __init__(self, message="", magic="Bitcoin Signed Message:\n"):
        object.__setattr__(self, 'message', message.encode("utf-8"))
        object.__setattr__(self, 'magic', magic.encode("utf-8"))

    @classmethod
    def stream_deserialize(cls, f):
        magic = bitcoin.core.serialize.BytesSerializer.stream_deserialize(f)
        message = bitcoin.core.serialize.BytesSerializer.stream_deserialize(f)
        return cls(message, magic)

    def stream_serialize(self, f):
        bitcoin.core.serialize.BytesSerializer.stream_serialize(self.magic, f)
        bitcoin.core.serialize.BytesSerializer.stream_serialize(self.message, f)

    def __repr__(self):
        return 'BitcoinMessage(%s, %s)' % (self.magic, self.message)


class Test_SignVerifyMessage(unittest.TestCase):
    def test_verify_message_simple(self):
        address = "1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G"
        message = address
        signature = "H85WKpqtNZDrajOnYDgUY+abh0KCAcOsAIOQwx2PftAbLEPRA7mzXA/CjXRxzz0MC225pR/hx02Vf2Ag2x33kU4="

        message = BitcoinMessage(message)

        self.assertTrue(VerifyMessage(address, message, signature))

    def test_verify_message_vectors(self):
        for vector in load_test_vectors('sign_verify_message.json'):
            message = BitcoinMessage(vector['address'])
            self.assertTrue(VerifyMessage(vector['address'], message, vector['signature']))

    def test_sign_message_simple(self):
        key = CBitcoinSecret("L4vB5fomsK8L95wQ7GFzvErYGht49JsCPJyJMHpB4xGM6xgi2jvG")
        address = "1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G"
        message = address

        message = BitcoinMessage(message)

        signature = SignMessage(key, message)

        print(signature)

        self.assertTrue(signature)

        self.assertTrue(VerifyMessage(address, message, signature))




if __name__ == "__main__":
    unittest.main()
