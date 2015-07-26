#!/usr/bin/env python

import unittest
import cryptovid
import os
import zbar
import Image
import base64
import hashlib

class CryptoVidTest(unittest.TestCase):

    def setUp(self):
        self.cv = cryptovid.CryptoVid()
        self.scanner = zbar.ImageScanner()
        self.scanner.parse_config('enable')
        if not os.path.isdir('./test'):
            raise Exception('Please run these tests from the main project directory')

    def test_encryption_text(self):
        plaintext = "Text text text text"
        key = "derive from this key"
        ciphertext = self.cv._encrypt(plaintext, key)
        deciphered = self.cv._decrypt(ciphertext, key)
        self.assertEqual(plaintext, deciphered)
        self.assertNotEqual(ciphertext, deciphered)

    def test_encryption_binary(self):
        data = b""
        key  = "justin bieber"
        with open('test/oag.jpg', 'rb') as f:
            data = f.read()
        ciphertext = self.cv._encrypt(base64.b64encode(data), key)
        deciphered = base64.b64decode(self.cv._decrypt(ciphertext, key))
        self.assertEqual(data, deciphered)
        self.assertNotEqual(ciphertext, deciphered)

    def test_qrcode_encoding_singleframe_text(self):
        data = "This is a basic ascii string"
        codes = self.cv._encode_to_qr_codes(data, False)
        self.assertEqual(len(codes), 1)
        pimage = Image.open(codes[0]).convert('L')
        width, height = pimage.size
        raw = pimage.tostring()
        stream = zbar.Image(width, height, 'Y800', raw)
        results = self.scanner.scan(stream)
        self.assertEqual(results, 1)
        for result in stream:
            self.assertEqual(str(result.type), 'QRCODE')
            self.assertEqual(base64.b64decode(result.data), data)

    def test_qrcode_encoding_binary(self):
        data = b""
        with open('test/fry.gif', 'rb') as f:
            data = f.read()
        codes = self.cv._encode_to_qr_codes(data, False)
        read_data = ""
        for code in codes:
            pimage = Image.open(code).convert('L')
            w, h = pimage.size
            raw = pimage.tostring()
            stream = zbar.Image(w, h, 'Y800', raw)
            results = self.scanner.scan(stream)
            has_qr_code = False
            for result in stream:
                if str(result.type) == 'QRCODE':
                    read_data += result.data
                    has_qr_code = True
            self.assertTrue(has_qr_code)
        data = base64.b64encode(data)
        self.assertEqual(data, read_data)

    def test_real_encode_decode(self):
        crypto_key = 'Why is a raven like a writing desk?'
        test_data = b""
        with open('test/fry.gif', 'rb') as f:
            test_data = f.read()
        encoded_video = self.cv.encode(test_data, crypto_key)
        decoded_video = self.cv.decode(encoded_video, crypto_key)
        with open('/tmp/test.gif', 'wb') as f:
            f.write(decoded_video)
        self.assertEqual(self._sha1('test/fry.gif'), self._sha1('/tmp/test.gif'))


    def _sha1(self, filepath):
        sha = hashlib.sha1()
        with open(filepath, 'rb') as f:
            while True:
                block = f.read(2**10) # Magic number: one-megabyte blocks.
                if not block: break
                sha.update(block)
        return sha.hexdigest()

    def _read_qr_code(self, filepath):
        pimage = Image.open(filepath).convert('L')
        w, h = pimage.size
        raw = pimage.tostring()
        stream = zbar.Image(w, h, 'Y800', raw)
        results = self.scanner.scan(stream)
        for result in stream:
            if str(result.type) == 'QRCODE':
                return result.data
        return None


if __name__ == '__main__':
    print "Running unit tests. Please wait, these take a while."
    unittest.main()
