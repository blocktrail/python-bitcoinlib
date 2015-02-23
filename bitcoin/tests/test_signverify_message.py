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

from bitcoin.core.key import CPubKey
from bitcoin.core.serialize import ImmutableSerializable
from bitcoin.wallet import P2PKHBitcoinAddress
import bitcoin
import base64


def VerifyMessage(address, message, sig):
    sig = base64.b64decode(sig)
    hash = message.GetHash()

    pubkey = CPubKey.recover_compact(hash, sig)

    return str(P2PKHBitcoinAddress.from_pubkey(pubkey)) == address


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
    def test_verify_message(self):
        address = "1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G"
        message = "1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G"
        signature = "H85WKpqtNZDrajOnYDgUY+abh0KCAcOsAIOQwx2PftAbLEPRA7mzXA/CjXRxzz0MC225pR/hx02Vf2Ag2x33kU4="

        message = BitcoinMessage(message)

        self.assertTrue(VerifyMessage(address, message, signature))


if __name__ == "__main__":
    unittest.main()
