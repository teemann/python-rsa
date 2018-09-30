# -*- coding: utf-8 -*-
#
#  Copyright 2011 Sybren A. Stüvel <sybren@stuvel.eu>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Tests PKCS #1 version 2 functionality.

Most of the mocked values come from the test vectors found at:
http://www.itomorrowmag.com/emc-plus/rsa-labs/standards-initiatives/pkcs-rsa-cryptography-standard.htm
"""

import unittest

from rsa import pkcs1_v2
from rsa import PublicKey, PrivateKey, randnum


public_key_data = b'''-----BEGIN PUBLIC KEY-----
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQCaAtwfiNnxnJLSUU6/oIoF/Zeq
kkkqnFswqAMct3Skxuk7Z16eqQKoFQEygsNbPJVJirJUjMPX1bLIhda/QIm6KR6e
RTuGGnnH8wTLxx53zMGpu9QmbpKWphKo5XKdEEnYuKId7B3TyZPJ2Sa09CygDpLe
xvJdmnZtgxZB1tFf9wIBJQ==
-----END PUBLIC KEY-----
'''

private_key_data = b'''-----BEGIN RSA PRIVATE KEY-----
MIICWQIBAAKBgQCaAtwfiNnxnJLSUU6/oIoF/ZeqkkkqnFswqAMct3Skxuk7Z16e
qQKoFQEygsNbPJVJirJUjMPX1bLIhda/QIm6KR6eRTuGGnnH8wTLxx53zMGpu9Qm
bpKWphKo5XKdEEnYuKId7B3TyZPJ2Sa09CygDpLexvJdmnZtgxZB1tFf9wIBJQKB
gFdpaC2S3JAMwgiqsCeSd9ni9TdMG7BmlJ8TQAlhNF2FpvgzwBTcdyEgracL8lZg
p8H0xhRP5Mab4gMbh7ioFtCNCynhx0uuqamDoPs41q88+eWl36v+m0myCQn9boL7
XKjF0FMW905rxSjWywFWGXsdsLLnWShDvQlJyBW4q+m9AkEA6Li4UyMNEX7jzJnZ
tW1HsjKfYmZ+oNmPVbuvng7eB5S2LaiTiXJjw+N//xgl/tDcDML5z6QXp3Qx6m0Q
P3PlLwJBAKlqnCdXzx5iP5PVaDOkpgR1OMd12koVI/IWSTOIp36X+S5yHI+J/jue
DhZ4HuPBKApz/xaMnXuo+ngwSEXND7kCQB9y6Hnv+tjZy8Gz7PzXao2z0Flny+w5
E16c0or7FxXH/PFpzr+L/6TZjdZdNZEjJKfHUjDQ/EcPs7flOYwIvhsCQFJrNzW8
A+VEjaHdcPaHc1wdWeR+hd7Z2iK+u9PhnZeINAjB5GGBZuySFLD8KrP9GmXzPdOe
WnOCo10QkdzEn90CQAwUY8PBc5cn7rzs/iJuWCYxARkHnCreiUcEbLFKG5NLZood
z4qdUGtAIoqhFg7b4gFyr62qNX7J6Xd2tYgX3DE=
-----END RSA PRIVATE KEY-----'''

enc_data = b'R\x16\xdb\xf0)H=\x13\xee\x08[\xc6\x8fC\xe5%\x99\xf3\xb6QX\x97k\xa8@\xb0\xcf\xe6\xb0Lp\x819\xff\x1bL\xc9' \
           b'\xb4\xb4\x1e\x01\x04\xc7\xcf\t\x03\x7f\xb9\x9f(\xa9\x8c\x13\xd2\xa1 55z\xef\xc1\x98\xd0\x11\xf6\x01\xb1' \
           b'\xf4\\\xe5\xf7\xc4\x07\xad\x8b\xfd\n\xf8\xd9\x9c\xa6\x82\xc4jX\x03\x02j\xe8}\x95\xd4\xa9\xbb\x0f\xd2,' \
           b'\x12\x8f\xa6\xe2\xab]P\x95\xcd\x91\x96\xc5\x0eo\xd8\xc9\xc7z4>\x05N\x15\xff\xe0\xb7\xe5\xb0\xb20\xe0'

sig_data = b'P\xd2Y\x81D\x87s\xf2\xb2L\x1c6\x81<\x91\xa9\xfc\x1d\xef\xd3\xbe\xe4D\xe1\x9c\xc2\xdf\xd4\x999\x1f\xf0\xb0\xfaU\r\xd33\xbb\xb7(\xde1D\x86\xac[1\xb9\x8c\x9f\x14\x9e\xf7f\x06\xbf\x07\x7f"iEH\xc3\x1b\xa4\xc59\x88\xc1\xa9\xeb\xb9Bo\xc8\'c\xb1\xae\x7fh0\x0f\xb5\xff\xdf\xed}\xac\xbd\x9a}\xde\x1d\x1b\xa3\x88b\x84(gP\xff\xbca^\xa9>c\xba\xbd\x8f\xb6\x85\x1e\x92\x90Z\x02\xd3\xc3\x06\x9b@a\xcc\x13'


class MGFTest(unittest.TestCase):
    def test_oaep_int_db_mask(self):
        seed = (
            b'\xaa\xfd\x12\xf6\x59\xca\xe6\x34\x89\xb4\x79\xe5\x07\x6d\xde\xc2'
            b'\xf0\x6c\xb5\x8f'
        )
        db = (
            b'\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90'
            b'\xaf\xd8\x07\x09\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xd4\x36\xe9\x95\x69'
            b'\xfd\x32\xa7\xc8\xa0\x5b\xbc\x90\xd3\x2c\x49'
        )
        masked_db = (
            b'\xdc\xd8\x7d\x5c\x68\xf1\xee\xa8\xf5\x52\x67\xc3\x1b\x2e\x8b\xb4'
            b'\x25\x1f\x84\xd7\xe0\xb2\xc0\x46\x26\xf5\xaf\xf9\x3e\xdc\xfb\x25'
            b'\xc9\xc2\xb3\xff\x8a\xe1\x0e\x83\x9a\x2d\xdb\x4c\xdc\xfe\x4f\xf4'
            b'\x77\x28\xb4\xa1\xb7\xc1\x36\x2b\xaa\xd2\x9a\xb4\x8d\x28\x69\xd5'
            b'\x02\x41\x21\x43\x58\x11\x59\x1b\xe3\x92\xf9\x82\xfb\x3e\x87\xd0'
            b'\x95\xae\xb4\x04\x48\xdb\x97\x2f\x3a\xc1\x4f\x7b\xc2\x75\x19\x52'
            b'\x81\xce\x32\xd2\xf1\xb7\x6d\x4d\x35\x3e\x2d'
        )

        # dbMask = MGF(seed, length(DB))
        db_mask = pkcs1_v2.mgf1(seed, length=len(db))
        expected_db_mask = (
            b'\x06\xe1\xde\xb2\x36\x9a\xa5\xa5\xc7\x07\xd8\x2c\x8e\x4e\x93\x24'
            b'\x8a\xc7\x83\xde\xe0\xb2\xc0\x46\x26\xf5\xaf\xf9\x3e\xdc\xfb\x25'
            b'\xc9\xc2\xb3\xff\x8a\xe1\x0e\x83\x9a\x2d\xdb\x4c\xdc\xfe\x4f\xf4'
            b'\x77\x28\xb4\xa1\xb7\xc1\x36\x2b\xaa\xd2\x9a\xb4\x8d\x28\x69\xd5'
            b'\x02\x41\x21\x43\x58\x11\x59\x1b\xe3\x92\xf9\x82\xfb\x3e\x87\xd0'
            b'\x95\xae\xb4\x04\x48\xdb\x97\x2f\x3a\xc1\x4e\xaf\xf4\x9c\x8c\x3b'
            b'\x7c\xfc\x95\x1a\x51\xec\xd1\xdd\xe6\x12\x64'
        )

        self.assertEqual(db_mask, expected_db_mask)

        # seedMask = MGF(maskedDB, length(seed))
        seed_mask = pkcs1_v2.mgf1(masked_db, length=len(seed))
        expected_seed_mask = (
            b'\x41\x87\x0b\x5a\xb0\x29\xe6\x57\xd9\x57\x50\xb5\x4c\x28\x3c\x08'
            b'\x72\x5d\xbe\xa9'
        )

        self.assertEqual(seed_mask, expected_seed_mask)

    def test_invalid_hasher(self):
        """Tests an invalid hasher generates an exception"""
        with self.assertRaises(ValueError):
            pkcs1_v2.mgf1(b'\x06\xe1\xde\xb2', length=8, hasher='SHA2')

    def test_invalid_length(self):
        with self.assertRaises(OverflowError):
            pkcs1_v2.mgf1(b'\x06\xe1\xde\xb2', length=2**50)

    def test_encrypt(self):
        pub_key = PublicKey.load_pkcs1_openssl_pem(public_key_data)
        ct = pkcs1_v2.encrypt(b'test', pub_key, test_seed=b'abcdefghijklmnopqrstuvwxyz'[:20])
        self.assertEqual(ct, enc_data)

    def test_decrypt(self):
        priv_key = PrivateKey.load_pkcs1(private_key_data)
        message = pkcs1_v2.decrypt(enc_data, priv_key)
        self.assertEqual(message, b'test')

    def test_sign(self):
        priv_key = PrivateKey.load_pkcs1(private_key_data)
        sig = pkcs1_v2.sign(b'test', priv_key, salt_len=0)
        self.assertEqual(sig, sig_data)

    def test_verify(self):
        pub_key = PublicKey.load_pkcs1_openssl_pem(public_key_data)
        ok = pkcs1_v2.verify(b'test', sig_data, pub_key, salt_len=0)
        self.assertTrue(ok)

    def test_many_encrypt_decrypt_fixed_data(self):
        priv_key = PrivateKey.load_pkcs1(private_key_data)
        pub_key = PublicKey.load_pkcs1_openssl_pem(public_key_data)
        all_enc = set()
        for i in range(100):
            try:
                data = b'a simple test message, which will be encrypted'
                enc = pkcs1_v2.encrypt(data, pub_key, hasher='SHA-256')
                dec = pkcs1_v2.decrypt(enc, priv_key, hasher='SHA-256')
                self.assertEqual(dec, data, i)
                all_enc.add(enc)
            except BaseException as e:
                self.assertIsNone(e, i)

        # Make sure the seed is doing what it's supposed to do
        # This test might (theoretically) fail, although it really shouldn't
        # A fail here might indicate a bad RNG
        self.assertGreater(len(all_enc), 1)

    def test_many_encrypt_decrypt(self):
        priv_key = PrivateKey.load_pkcs1(private_key_data)
        pub_key = PublicKey.load_pkcs1_openssl_pem(public_key_data)
        for i in range(100):
            try:
                data = randnum.read_random_bits(16 * 8)
                enc = pkcs1_v2.encrypt(data, pub_key, hasher='SHA-256')
                dec = pkcs1_v2.decrypt(enc, priv_key, hasher='SHA-256')
                self.assertEqual(dec, data, i)
            except BaseException as e:
                self.assertIsNone(e, i)

    def test_many_sign_verify_fixed_data(self):
        priv_key = PrivateKey.load_pkcs1(private_key_data)
        pub_key = PublicKey.load_pkcs1_openssl_pem(public_key_data)
        all_signatures = set()
        for i in range(100):
            try:
                data = b'a simple test message, which will be signed'
                signature = pkcs1_v2.sign(data, priv_key, hasher='SHA-256')
                self.assertTrue(pkcs1_v2.verify(data, signature, pub_key, hasher='SHA-256'), i)
                all_signatures.add(signature)
            except BaseException as e:
                self.assertIsNone(e, i)

        # Make sure the salt is doing what it's supposed to do
        # This test might (theoretically) fail, although it really shouldn't
        # A fail here might indicate a bad RNG
        self.assertGreater(len(all_signatures), 1)

    def test_many_sign_verify(self):
        priv_key = PrivateKey.load_pkcs1(private_key_data)
        pub_key = PublicKey.load_pkcs1_openssl_pem(public_key_data)
        for i in range(100):
            try:
                data = randnum.read_random_bits(16 * 8)
                signature = pkcs1_v2.sign(data, priv_key, hasher='SHA-256')
                self.assertTrue(pkcs1_v2.verify(data, signature, pub_key, hasher='SHA-256'), i)
            except BaseException as e:
                self.assertIsNone(e, i)
