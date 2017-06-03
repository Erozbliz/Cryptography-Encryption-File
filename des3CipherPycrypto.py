import base64
import hashlib

from Crypto import Random
from Crypto.Cipher import DES3

class TDESCipher(object):
    """
    Triple DES (Data Encryption Standard)
    Enchaine 3 applications successives de l'algorithme DES sur le meme bloc de donnees de 64 bits, avec 2 ou 3 clef DES differentes.
    Le TDES est cryptographiquement securise, il n'est ni aussi sur ni aussi rapide que AES.
    Taille(s) du bloc       : 64 bits (8 octets)
    Longueur(s) de la cle   : 168(21)ou 112(14) bits
    Nombre de tours 3x16 tours du DES
    """
    def __init__(self, key):
        #taille block (en octets)
        self.bs = 8
        #clef
        self.key = key

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    #padding permettant d'utiliser n'importe quelle taille de message
    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * TDESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = self._pad(TDESCipher.str_to_bytes(raw))
        iv = Random.new().read(DES3.block_size)
        cipher = DES3.new(self.key, DES3.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:DES3.block_size]
        cipher = DES3.new(self.key, DES3.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[DES3.block_size:])).decode('utf-8')

    def encryptByte(self, raw):
        raw = self._pad(TDESCipher.str_to_bytes(raw))
        iv = Random.new().read(DES3.block_size)
        cipher = DES3.new(self.key, DES3.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decryptByte(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:DES3.block_size]
        cipher = DES3.new(self.key, DES3.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[DES3.block_size:]))

