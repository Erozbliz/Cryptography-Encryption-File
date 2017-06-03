# pyCrypto.AES file encoding example based on 
# Eli Bendersky post (http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto/)

from Crypto.Cipher import AES
from Crypto import Random
import os
import random
import struct
import hashlib


def create_source_file(file_name):
    f = open(file_name, "wt")
    f.write("Hello!\nThis is an example text file.")
    f.close()


def write_file(file_name, data):
    f = open(file_name, "w")
    f.write(data)
    f.close()


def encrypt_file(key, in_filename, out_filename=None, chunksize=64 * 1024):
    """ Encrypts a file using AES (CBC mode) with the
        given key.
        key:
            The encryption key - a string that must be
            either 16, 24 or 32 bytes long. Longer keys
            are more secure.
        in_filename:
            Name of the input file
        out_filename:
            If None, '<in_filename>.enc' will be used.
        chunksize:
            Sets the size of the chunk which the function
            uses to read and encrypt the file. Larger chunk
            sizes can be faster for some files and machines.
            chunksize must be divisible by 16.
    """
    if not out_filename:
        out_filename = in_filename + '.enc'

    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))


def decrypt_file(key, in_filename, out_filename=None, chunksize=24 * 1024):
    """ Decrypts a file using AES (CBC mode) with the
        given key. Parameters are similar to encrypt_file,
        with one difference: out_filename, if not supplied
        will be in_filename without its last extension
        (i.e. if in_filename is 'aaa.zip.enc' then
        out_filename will be 'aaa.zip')
    """
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)


def md5_for_file(file_name, block_size=2 ** 20):
    md5 = hashlib.md5()
    f = open(file_name, "r")

    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)

    f.close()
    return md5.hexdigest()


source_file_name = "1-source.txt"
encoded_file_name = "2-encoded.txt"
decoded_file_name = "3-decoded.txt"

create_source_file(source_file_name)

# Length could be 16, 14 or 32
key = Random.get_random_bytes(16)
encrypt_file(key, source_file_name, encoded_file_name)
decrypt_file(key, encoded_file_name, decoded_file_name)

source_md5 = md5_for_file(source_file_name)
decoded_md5 = md5_for_file(decoded_file_name)

#print "Source: %s [%s]" % (source_file_name, source_md5)
#print "Encoded: %s" % (source_file_name)
#print "Decoded: %s [%s]" % (decoded_file_name, decoded_md5)
#print "Hash check %s" % "passed" if source_md5 == decoded_md5 else "not passed"