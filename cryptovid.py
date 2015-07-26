#!/usr/bin/env python

import argparse

# system utils
import getpass
import glob
import math
import os
import shutil
import subprocess
import sys
import time

# serialization, string handling
import base64
import pipes

# image processing
import Image
import multiprocessing
import qrcode
import zbar

# cryptography
import hashlib
from pbkdf2 import PBKDF2
import nacl.utils
from nacl.secret import SecretBox

class CryptoVidException(Exception):
    pass

class CryptoVid(object):
    staging_dir_root = '/tmp'
    staging_dir = 'cv'
    cpu_count = multiprocessing.cpu_count()

    def __init__(self):
        self.staging_dir = 'cv_' + self._get_tmp_path('staging_dir')
        self.staging_path = os.path.join(self.staging_dir_root, self.staging_dir)
        if not os.path.isdir(self.staging_path):
            os.mkdir(self.staging_path)

    def __del__(self):
        self.close()

    def close(self):
        if os.path.exists(self.staging_path):
            shutil.rmtree(self.staging_path)

    def encode(self, bin_data, key, clean_up_tmp_files=True):
        ciphertext = self._encrypt(bin_data, key)
        qr_code_pattern = self._encode_to_qr_codes(ciphertext)
        tmp_video_file = self._stitch_images_to_video(qr_code_pattern)
        if clean_up_tmp_files:
            shutil.rmtree(os.path.dirname(qr_code_pattern))
        return tmp_video_file

    def decode(self, video_file_path, key, clean_up_tmp_files=True):
        qr_code_list = self._rip_video_to_images(video_file_path)
        ciphertext = self._decode_from_qr_codes(qr_code_list)
        if clean_up_tmp_files:
            shutil.rmtree(os.path.dirname(qr_code_list[0]))
        plaintext = self._decrypt(ciphertext, key)
        return plaintext

    def _encrypt(self, bin_data, key):
        key_data = self._get_key(key)
        public_box = SecretBox(key_data[1])
        return str(key_data[0]) + ':::' + str(public_box.encrypt(bin_data, self._get_nonce()))

    def _decrypt(self, bin_data, key):
        bin_data = bin_data.split(':::')
        derived_key = self._get_key(key, bin_data[0])
        private_box = SecretBox(derived_key[1])
        return str(private_box.decrypt(bin_data[1]))

    def _get_nonce(self):
        return nacl.utils.random(SecretBox.NONCE_SIZE)

    def _get_key(self, key, salt=None):
        if salt is None:
            salt = self._get_nonce()
        return (salt, PBKDF2(str(key), salt).read(SecretBox.KEY_SIZE))

    def _encode_to_qr_codes(self, bin_data, return_pattern=True):
        bin_data = base64.b64encode(bin_data)
        max_bytes_per_qr_code = 600
        chunks = [bin_data[i:i+max_bytes_per_qr_code] for i in range(0, len(bin_data), max_bytes_per_qr_code)]

        tmp_path = os.path.join(self.staging_path, self._get_tmp_path('encode'))
        os.mkdir(tmp_path)
        if not os.path.isdir(tmp_path):
            raise CryptoVidException("failed to make tmp path for QR %s" % tmp_path)

        pool = multiprocessing.Pool(processes=self.cpu_count)
        for i in xrange(len(chunks)):
            chunks[i] = (i, tmp_path, chunks[i])
        files = pool.map(_qrcode_gen_worker, chunks)
        files = sorted(files)

        if not return_pattern:
            return files
        else:
            return os.path.join(tmp_path, "qrcode%015d.png")

    def _decode_from_qr_codes(self, img_filename_list):
        pool = multiprocessing.Pool(processes=self.cpu_count)
        img_filename_list = sorted(img_filename_list)
        file_data = pool.map(_qrcode_read_worker, img_filename_list)
        return base64.b64decode(''.join(file_data))

    def _stitch_images_to_video(self, jpeg_filename_pattern, outfile=None):
        path = os.path.join(os.path.dirname(jpeg_filename_pattern), '*.png')
        if outfile is None:
            outfile = os.path.join(self.staging_path, "video_%s.mp4" % self._get_tmp_path('stitch'))
        devnull = open(os.devnull, 'w')

        path = pipes.quote(path)
        outfile = pipes.quote(outfile)

        cmd = "ffmpeg -threads %d -f image2 -pattern_type glob -i %s -s 720x720 -vcodec libx264 %s" % (self.cpu_count, path, outfile)
        subprocess.call(cmd, shell=True, stdout=devnull, stderr=devnull)
        devnull.close()
        return outfile

    def _rip_video_to_images(self, video_file_name, outdir=None):
        if outdir is None:
            outdir = os.path.join(self.staging_path, "%s" % self._get_tmp_path('rip'))
            if not os.path.isdir(outdir):
                os.mkdir(outdir)
        outpath = os.path.join(outdir, 'ext_qrcode%015d.png')
        devnull = open(os.devnull, 'w')

        video_file_name = pipes.quote(video_file_name)
        outpath = pipes.quote(outpath)

        cmd = "ffmpeg -threads %d -y -i %s -s 720x720 %s" % (self.cpu_count, video_file_name, outpath)
        subprocess.call(cmd, shell=True, stdout=devnull, stderr=devnull)
        devnull.close()
        return sorted(glob.glob(os.path.join(outdir, "*.png")))

    def _get_tmp_path(self, seed=''):
        h = hashlib.md5()
        h.update(str(time.time()) + base64.b64encode(os.urandom(4)) + str(seed))
        return h.hexdigest()

# worker function for multiprocessing.Pool
def _qrcode_gen_worker(chunk_tuple):
    file_num = chunk_tuple[0]
    tmp_path = chunk_tuple[1]
    data_chunk = chunk_tuple[2]

    qr = qrcode.QRCode(version=15,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=8, border=4)
    qr.add_data(data_chunk)
    qr.make()
    qr_sequence = "qrcode%015d.png" % file_num
    filepath = os.path.join(tmp_path, qr_sequence)
    qr.make_image().save(filepath)
    return filepath

def _qrcode_read_worker(filepath):
    if os.path.isfile(filepath):
        pil = Image.open(filepath).convert('L')
        w,h = pil.size
        raw = pil.tostring()
        stream = zbar.Image(w, h, 'Y800', raw)
        scanner = zbar.ImageScanner()
        scanner.parse_config('enable')
        results = scanner.scan(stream)
        if results is 0:
            return None
        else:
            for result in stream:
                if str(result.type) == 'QRCODE':
                    return result.data
            return None
    return None

def main(args):
    if not os.path.exists(args.input_file) or not os.path.isfile(args.input_file):
        print "ERR: input file %s is not a file" % args.input_file
        sys.exit(1)

    if not os.path.exists(os.path.dirname(os.path.abspath(args.output_file))):
        print "ERR: no path exists to save output to %s" % args.output_file
        sys.exit(1)

    if not args.encode and not args.decode:
        print "ERR: Must select one of --encode or --decode"
        sys.exit(1)

    key_material = ""
    if args.keyfile:
        if os.path.exists(args.keyfile):
            with open(args.keyfile, 'rb') as f:
                key_material = f.read(16384)
        else:
            print "Could not find keyfile %s" % args.keyfile
            sys.exit(1)
    if (args.keyfile and args.prompt_for_passphrase) or not args.keyfile:
        pass1 = getpass.getpass('Passphrase: ')
        pass2 = getpass.getpass('Confirm passphrase: ')
        if pass1 != pass2:
            print "ERR: Passphrases do not match"
            sys.exit(1)
        else:
            key_material += pass1

    v = CryptoVid()
    v.cpu_count = args.cpu_count

    if args.encode:
        print "Encoding %s to %s" % (args.input_file, args.output_file)
        file_data = open(args.input_file, 'rb').read()
        tmp_file = v.encode(file_data, key_material)
        shutil.copy(tmp_file, args.output_file)
        os.unlink(tmp_file)

    if args.decode:
        print "Decoding %s to %s" % (args.input_file, args.output_file)
        try:
            file_data = v.decode(args.input_file, key_material)
        except nacl.exceptions.CryptoError:
            print "ERR: Could not decrypt file."
        with open(args.output_file, 'wb') as f:
            f.write(file_data)

    v.close()
    sys.exit(0)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(
            description="Encode or decode an encrypted video containing arbitrary data.")
    ap.add_argument('--cpu-count', default=multiprocessing.cpu_count(),
                    help="Number of CPUs to use when encoding.")
    ap.add_argument('--keyfile', help="A keyfile to use for a crypto key. Uses first 16KB.")
    ap.add_argument('--prompt-for-passphrase', help="Prompt for passphrase if keyfile is used.", default=False, action="store_true")
    ap.add_argument('--passphrase', help="The passphrase to use for a crypto key. Disclosing this on the command line may be dangerous.")
    ap.add_argument('--decode', help="Decrypt video to data.", action='store_true')
    ap.add_argument('--encode', help="Encode data to video.", action='store_true')
    ap.add_argument('input_file')
    ap.add_argument('output_file')
    main(ap.parse_args())
