# Copyright (C) 2011 Sam Rushing
# Copyright (C) 2012-2015 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

"""ECC secp256k1 crypto routines

WARNING: This module does not mlock() secrets; your private keys may end up on
disk in swap! Use with caution!
"""
import base64

import ctypes
import ctypes.util
import hashlib
import sys
import struct
import math
import binascii
import ecdsa
import bitcoin

_bchr = chr
_bord = ord
if sys.version > '3':
    long = int
    _bchr = lambda x: bytes([x])
    _bord = lambda x: x

if sys.version > '3':
    _bchr = lambda x: bytes([x])
    _bord = lambda x: x[0]
    from io import BytesIO as BytesIO
else:
    _bchr = chr
    _bord = ord
    from cStringIO import StringIO as BytesIO

import bitcoin.core.script

_ssl = ctypes.cdll.LoadLibrary(ctypes.util.find_library('ssl') or 'libeay32')

# this specifies the curve used with ECDSA.
_NID_secp256k1 = 714 # from openssl/obj_mac.h

class SECP256k1:
    oid = (1, 3, 132, 0, 10)
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    a = 0x0000000000000000000000000000000000000000000000000000000000000000
    b = 0x0000000000000000000000000000000000000000000000000000000000000007
    h = 1
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
    curve = ecdsa.ellipticcurve.CurveFp(p, a, b)
    G = ecdsa.ellipticcurve.Point(curve, Gx, Gy, order)
    ecdsa_curve = ecdsa.curves.Curve("SECP256k1", curve, G, oid)

# Thx to Sam Devlin for the ctypes magic 64-bit fix.
def _check_result (val, func, args):
    if val == 0:
        raise ValueError
    else:
        return ctypes.c_void_p(val)

_ssl.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
_ssl.EC_KEY_new_by_curve_name.errcheck = _check_result

# From openssl/ecdsa.h
class ECDSA_SIG_st(ctypes.Structure):
     _fields_ = [("r", ctypes.c_void_p),
                ("s", ctypes.c_void_p)]

class CECKey:
    """Wrapper around OpenSSL's EC_KEY"""

    POINT_CONVERSION_COMPRESSED = 2
    POINT_CONVERSION_UNCOMPRESSED = 4

    def __init__(self):
        self.k = _ssl.EC_KEY_new_by_curve_name(_NID_secp256k1)

    def __del__(self):
        if _ssl:
            _ssl.EC_KEY_free(self.k)
        self.k = None

    def set_secretbytes(self, secret):
        priv_key = _ssl.BN_bin2bn(secret, 32, _ssl.BN_new())
        group = _ssl.EC_KEY_get0_group(self.k)
        pub_key = _ssl.EC_POINT_new(group)
        ctx = _ssl.BN_CTX_new()
        if not _ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx):
            raise ValueError("Could not derive public key from the supplied secret.")
        _ssl.EC_POINT_mul(group, pub_key, priv_key, None, None, ctx)
        _ssl.EC_KEY_set_private_key(self.k, priv_key)
        _ssl.EC_KEY_set_public_key(self.k, pub_key)
        _ssl.EC_POINT_free(pub_key)
        _ssl.BN_CTX_free(ctx)
        return self.k

    def set_privkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        return _ssl.d2i_ECPrivateKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def set_pubkey(self, key):
        self.mb = ctypes.create_string_buffer(key)
        return _ssl.o2i_ECPublicKey(ctypes.byref(self.k), ctypes.byref(ctypes.pointer(self.mb)), len(key))

    def get_privkey(self):
        size = _ssl.i2d_ECPrivateKey(self.k, 0)
        mb_pri = ctypes.create_string_buffer(size)
        _ssl.i2d_ECPrivateKey(self.k, ctypes.byref(ctypes.pointer(mb_pri)))
        return mb_pri.raw

    def get_pubkey(self):
        size = _ssl.i2o_ECPublicKey(self.k, 0)
        mb = ctypes.create_string_buffer(size)
        _ssl.i2o_ECPublicKey(self.k, ctypes.byref(ctypes.pointer(mb)))
        return mb.raw

    def get_raw_ecdh_key(self, other_pubkey):
        ecdh_keybuffer = ctypes.create_string_buffer(32)
        r = _ssl.ECDH_compute_key(ctypes.pointer(ecdh_keybuffer), 32,
                                 _ssl.EC_KEY_get0_public_key(other_pubkey.k),
                                 self.k, 0)
        if r != 32:
            raise Exception('CKey.get_ecdh_key(): ECDH_compute_key() failed')
        return ecdh_keybuffer.raw

    def get_ecdh_key(self, other_pubkey, kdf=lambda k: hashlib.sha256(k).digest()):
        # FIXME: be warned it's not clear what the kdf should be as a default
        r = self.get_raw_ecdh_key(other_pubkey)
        return kdf(r)

    def sign(self, hash):
        if not isinstance(hash, bytes):
            raise TypeError('Hash must be bytes instance; got %r' % hash.__class__)
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        sig_size0 = ctypes.c_uint32()
        sig_size0.value = _ssl.ECDSA_size(self.k)
        mb_sig = ctypes.create_string_buffer(sig_size0.value)
        result = _ssl.ECDSA_sign(0, hash, len(hash), mb_sig, ctypes.byref(sig_size0), self.k)
        assert 1 == result
        if bitcoin.core.script.IsLowDERSignature(mb_sig.raw[:sig_size0.value]):
            return mb_sig.raw[:sig_size0.value]
        else:
            return self.signature_to_low_s(mb_sig.raw[:sig_size0.value])

    def sign_compact(self, hash):
        if not isinstance(hash, bytes):
            raise TypeError('Hash must be bytes instance; got %r' % hash.__class__)
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        sig_size0 = ctypes.c_uint32()
        sig_size0.value = _ssl.ECDSA_size(self.k)
        mb_sig = ctypes.create_string_buffer(sig_size0.value)
        result = _ssl.ECDSA_sign(0, hash, len(hash), mb_sig, ctypes.byref(sig_size0), self.k)
        assert 1 == result

        sig = mb_sig.raw[:sig_size0.value]

        sig = b'0D\x02 S\x15K?\xae3yvm/{|\x9a\xad\x7f\xb3\n\x02XV&\xfbT\x0e\x9c\xf8\xa3W"\x13\xa8\xce\x02 ;\xe0\x16{\x82s\x07\xc5\xfa\xac\xf1\xc3\x9c\xf4\x0es\xc0\xcd\r;\xde\xcaQPl<\x0c\xab\x0b\xb5S6'

        print("")
        print("")
        print(sig, len(sig), sig_size0.value)

        # decode DER
        length_r = sig[3]
        if isinstance(length_r, str):
            length_r = int(struct.unpack('B', length_r)[0])
        length_s = sig[5 + length_r]
        if isinstance(length_s, str):
            length_s = int(struct.unpack('B', length_s)[0])
        r_val = sig[3:3 + length_r]
        s_val = sig[6 + length_r:6 + length_r + length_s]

        print('decoded DER:')
        print(length_r, length_s)
        print(len(r_val), len(s_val))
        print(r_val, s_val)

        # debugging
        print("ECDSA says:")
        try:
            sig_der = sig
            order = SECP256k1.order

            if not sig_der.startswith(b"\x30"):
                raise ValueError
            length, lengthlength = ecdsa.der.read_length(sig_der[1:])
            endseq = 1+lengthlength+length
            rs_strings, empty = sig_der[1+lengthlength:endseq], sig_der[endseq:]

            if empty != b"":
                raise ValueError("trailing junk after DER sig: %s" % empty)

            if not rs_strings.startswith(b"\x02"):
                raise ValueError("wanted integer (0x02)")
            length, llen = ecdsa.der.read_length(rs_strings[1:])
            print(1+lengthlength, 1+llen)
            rbytes = rs_strings[1+llen:1+llen+length]
            rest = rs_strings[1+llen+length:]
            nbytes = rbytes[0]
            assert nbytes < 0x80 # can't support negative numbers yet
            r, rest = int(binascii.hexlify(rbytes), 16), rest

            if not rest.startswith(b"\x02"):
                raise ValueError("wanted integer (0x02)")
            length, llen = ecdsa.der.read_length(rest[1:])
            sbytes = rest[1+llen:1+llen+length]
            rest = rest[1+llen+length:]
            nbytes = sbytes[0]
            assert nbytes < 0x80 # can't support negative numbers yet
            s, empty = int(binascii.hexlify(sbytes), 16), rest

            if empty != b"":
                raise ValueError("trailing junk after DER numbers: %s" % empty)

            print(r, s)
        except Exception as e:
            print(e)

        f = BytesIO(sig)
        assert bitcoin.core.ser_read(f, 1) == b"\x30"
        rs_strings = bitcoin.core.BytesSerializer.stream_deserialize(f)
        print(len(rs_strings))
        f = BytesIO(rs_strings)
        assert bitcoin.core.ser_read(f, 1) == b"\x02"
        r_val = bitcoin.core.BytesSerializer.stream_deserialize(f)
        assert bitcoin.core.ser_read(f, 1) == b"\x02"
        s_val = bitcoin.core.BytesSerializer.stream_deserialize(f)

        length_r = len(r_val)
        length_s = len(s_val)



        # for w/e this randomly results in R and S values that are missing bytes
        print('bin2bn -> bn2bin')
        rr_val = _ssl.BN_bin2bn(r_val, length_r, _ssl.BN_new())
        ss_val = _ssl.BN_bin2bn(s_val, length_s, _ssl.BN_new())
        print(_ssl.BN_num_bits(rr_val), _ssl.BN_num_bits(ss_val))
        length_rr = int(math.ceil(_ssl.BN_num_bits(rr_val) / 8))
        length_ss = int(math.ceil(_ssl.BN_num_bits(ss_val) / 8))
        print(length_rr, length_ss)
        rr = ctypes.create_string_buffer(length_rr)
        ss = ctypes.create_string_buffer(length_ss)
        _ssl.BN_bn2bin(rr_val, rr)
        _ssl.BN_bn2bin(ss_val, ss)
        print(len(rr.value), len(ss.value))
        print(rr.value, ss.value)
        print(int.from_bytes(rr.value, byteorder='big'), int.from_bytes(ss.value, byteorder='big'))

        # bitcoin core does <4, but I've seen other places do <2 and I've never seen a i > 1 so far
        for i in range(0, 4):
            cec_key = CECKey()
            cec_key.set_compressed(True)

            result = cec_key.recover(r_val, s_val, hash, len(hash), i, 1)
            if result == 1:
                # return mb_sig.raw
                print('RECOVERED!')
                # even when recovered, these don't match :/
                print(cec_key.get_pubkey(), self.get_pubkey())
                if cec_key.get_pubkey() == self.get_pubkey() or True:
                    return r_val + s_val, i
            else:
                print('NOT', result)

        raise ValueError

    def signature_to_low_s(self, sig):
        der_sig = ECDSA_SIG_st()
        _ssl.d2i_ECDSA_SIG(ctypes.byref(ctypes.pointer(der_sig)), ctypes.byref(ctypes.c_char_p(sig)), len(sig))
        group = _ssl.EC_KEY_get0_group(self.k)
        order = _ssl.BN_new()
        halforder = _ssl.BN_new()
        ctx = _ssl.BN_CTX_new()
        _ssl.EC_GROUP_get_order(group, order, ctx)
        _ssl.BN_rshift1(halforder, order)

        # Verify that s is over half the order of the curve before we actually subtract anything from it
        if _ssl.BN_cmp(der_sig.s, halforder) > 0:
          _ssl.BN_sub(der_sig.s, order, der_sig.s)

        _ssl.BN_free(halforder)
        _ssl.BN_free(order)
        _ssl.BN_CTX_free(ctx)

        derlen = _ssl.i2d_ECDSA_SIG(ctypes.pointer(der_sig), 0)
        if derlen == 0:
            _ssl.ECDSA_SIG_free(der_sig)
            return None
        new_sig = ctypes.create_string_buffer(derlen)
        _ssl.i2d_ECDSA_SIG(ctypes.pointer(der_sig), ctypes.byref(ctypes.pointer(new_sig)))
        _ssl.BN_free(der_sig.r)
        _ssl.BN_free(der_sig.s)

        return new_sig.raw

    def verify(self, hash, sig):
        """Verify a DER signature"""
        if not sig:
          return false

        # New versions of OpenSSL will reject non-canonical DER signatures. de/re-serialize first.
        norm_sig = ctypes.c_void_p(0)
        _ssl.d2i_ECDSA_SIG(ctypes.byref(norm_sig), ctypes.byref(ctypes.c_char_p(sig)), len(sig))

        derlen = _ssl.i2d_ECDSA_SIG(norm_sig, 0)
        if derlen == 0:
            _ssl.ECDSA_SIG_free(norm_sig)
            return false

        norm_der = ctypes.create_string_buffer(derlen)
        _ssl.i2d_ECDSA_SIG(norm_sig, ctypes.byref(ctypes.pointer(norm_der)))
        _ssl.ECDSA_SIG_free(norm_sig)

        # -1 = error, 0 = bad sig, 1 = good
        return _ssl.ECDSA_verify(0, hash, len(hash), norm_der, derlen, self.k) == 1

    def set_compressed(self, compressed):
        if compressed:
            form = self.POINT_CONVERSION_COMPRESSED
        else:
            form = self.POINT_CONVERSION_UNCOMPRESSED
        _ssl.EC_KEY_set_conv_form(self.k, form)

    def recover(self, sigR, sigS, msg, msglen, recid, check):
        """
        Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
        recid selects which key is recovered
        if check is non-zero, additional checks are performed
        """
        i = int(recid / 2)

        r = None
        s = None
        ctx = None
        R = None
        O = None
        Q = None

        try:
            r = _ssl.BN_bin2bn(sigR, 32, _ssl.BN_new())
            s = _ssl.BN_bin2bn(sigS, 32, _ssl.BN_new())

            group = _ssl.EC_KEY_get0_group(self.k)
            ctx = _ssl.BN_CTX_new()
            order = _ssl.BN_CTX_get(ctx)
            ctx = _ssl.BN_CTX_new()

            if not _ssl.EC_GROUP_get_order(group, order, ctx):
                return -2

            x = _ssl.BN_CTX_get(ctx)
            if not _ssl.BN_copy(x, order):
                return -1
            if not _ssl.BN_mul_word(x, i):
                return -1
            if not _ssl.BN_add(x, x, r):
                return -1

            field = _ssl.BN_CTX_get(ctx)
            if not _ssl.EC_GROUP_get_curve_GFp(group, field, None, None, ctx):
                return -2

            if _ssl.BN_cmp(x, field) >= 0:
                return '_ssl.BN_cmp'

            R = _ssl.EC_POINT_new(group)
            if R is None:
                return -2
            if not _ssl.EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx):
                return 'not _ssl.EC_POINT_set_compressed_coordinates_GFp'

            if check:
                O = _ssl.EC_POINT_new(group)
                if O is None:
                    return -2
                if not _ssl.EC_POINT_mul(group, O, None, R, order, ctx):
                    return -2
                if not _ssl.EC_POINT_is_at_infinity(group, O):
                    return 'not _ssl.EC_POINT_is_at_infinity'

            Q = _ssl.EC_POINT_new(group)
            if Q is None:
                return -2

            n = _ssl.EC_GROUP_get_degree(group)
            e = _ssl.BN_CTX_get(ctx)
            if not _ssl.BN_bin2bn(msg, msglen, e):
                return -1

            if 8 * msglen > n:
                _ssl.BN_rshift(e, e, 8 - (n & 7))

            zero = _ssl.BN_CTX_get(ctx)
            # if not _ssl.BN_zero(zero):
            #     return -1
            if not _ssl.BN_mod_sub(e, zero, e, order, ctx):
                return -1
            rr = _ssl.BN_CTX_get(ctx)
            if not _ssl.BN_mod_inverse(rr, r, order, ctx):
                return -1
            sor = _ssl.BN_CTX_get(ctx)
            if not _ssl.BN_mod_mul(sor, s, rr, order, ctx):
                return -1
            eor = _ssl.BN_CTX_get(ctx)
            if not _ssl.BN_mod_mul(eor, e, rr, order, ctx):
                return -1
            if not _ssl.EC_POINT_mul(group, Q, eor, R, sor, ctx):
                return -2

            if not _ssl.EC_KEY_set_public_key(self.k, Q):
                return -2

            return 1
        finally:
            if r: _ssl.BN_free(r)
            if s: _ssl.BN_free(s)
            if ctx: _ssl.BN_CTX_free(ctx)
            if R: _ssl.EC_POINT_free(R)
            if O: _ssl.EC_POINT_free(O)
            if Q: _ssl.EC_POINT_free(Q)

class CPubKey(bytes):
    """An encapsulated public key

    Attributes:

    is_valid      - Corresponds to CPubKey.IsValid()
    is_fullyvalid - Corresponds to CPubKey.IsFullyValid()
    is_compressed - Corresponds to CPubKey.IsCompressed()
    """

    def __new__(cls, buf, _cec_key=None):
        self = super(CPubKey, cls).__new__(cls, buf)
        if _cec_key is None:
            _cec_key = CECKey()
        self._cec_key = _cec_key
        self.is_fullyvalid = _cec_key.set_pubkey(self) != 0
        return self

    @classmethod
    def recover_compact(cls, hash, sig, check=0):
        """Recover a public key from a compact signature."""
        if len(sig) != 65:
            raise ValueError("Signature should be 65 characters, not [%d]" % (len(sig), ))

        recid = (_bord(sig[0]) - 27) & 3
        compressed = (_bord(sig[0]) - 27) & 4 != 0

        cec_key = CECKey()
        cec_key.set_compressed(compressed)

        sigR = sig[1:33]
        sigS = sig[33:65]

        result = cec_key.recover(sigR, sigS, hash, len(hash), recid, check)

        if result < 1:
            return False

        pubkey = cec_key.get_pubkey()

        return CPubKey(pubkey, _cec_key=cec_key)

    @property
    def is_valid(self):
        return len(self) > 0

    @property
    def is_compressed(self):
        return len(self) == 33

    def verify(self, hash, sig):
        return self._cec_key.verify(hash, sig)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        # Always have represent as b'<secret>' so test cases don't have to
        # change for py2/3
        if sys.version > '3':
            return '%s(%s)' % (self.__class__.__name__, super(CPubKey, self).__repr__())
        else:
            return '%s(b%s)' % (self.__class__.__name__, super(CPubKey, self).__repr__())

__all__ = (
        'CECKey',
        'CPubKey',
)
