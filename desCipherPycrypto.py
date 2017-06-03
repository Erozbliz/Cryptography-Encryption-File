import base64
import hashlib

from Crypto import Random
from Crypto.Cipher import DES


class DESCipher(object):
    """
    Data Encryption Standard (DES)
    DES est cryptographiquement securise, mais sa longueur cle est trop courte
    DES est vulnerable au bruteforce
    Taille(s) du bloc       : 64 bits (8)
    Longueur(s) de la cle   : 56 bits (7) + 8 bits de parite (1)
    Nombre de tours 16 tours du DES
    """
    def __init__(self, key):
        #taille block (en octets)
        self.bs = 8
        #clef de 8 octets
        self.key = key

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    #padding permettant d'utiliser n'importe quelle taille de message
    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * DESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = self._pad(DESCipher.str_to_bytes(raw))
        #iv = Random.new().read(DES.block_size)
        iv = (b"\xad\xf7\xe6\xab\x88\xd3\x15\x0f")
        #print(iv)
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:DES.block_size]
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[DES.block_size:])).decode('utf-8')

    def encryptByte(self, raw):
        raw = self._pad(DESCipher.str_to_bytes(raw))
        iv = Random.new().read(DES.block_size)
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decryptByte(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:DES.block_size]
        cipher = DES.new(self.key, DES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[DES.block_size:]))

