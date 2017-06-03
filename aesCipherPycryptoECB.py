import base64
import hashlib

from Crypto import Random
from Crypto.Cipher import AES


class AESCipher(object):
    """
    Cryptage AES, Rijndael
    Peut utiliser n'importe quelle taille de donnees et taille de mot de passe grace au padding
    On manipule en octet pour garantir l'integrite des donnees
    Taille(s) du bloc       : 128 bits (16 octets)
    Longueur(s) de la clef  : 128(16), 192(24), 256(32) bits(octets)
    Nombre de tours         : 10,12,14 selon la taille de la clef
    Utilisation de : ECB Les blocs sont chiffrés indépendamment bloc par bloc
    Liste des blocks
    https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.blockalgo-module.html#MODE_OPENPGP
    """
    def __init__(self, key):
        #taille block (en octets)
        self.bs = 16
        #clef 256 bits (32 octets)
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()
        #self.key = key

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    #padding permettant d'utiliser n'importe quelle taille de message
    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_ECB, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_ECB, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def encryptByte(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_ECB, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decryptByte(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_ECB, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

