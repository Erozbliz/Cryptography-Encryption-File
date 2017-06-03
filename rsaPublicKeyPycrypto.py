import base64
import hashlib

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP



class RSAPublicKey(object):
    """

    """
    def __init__(self):
        self.bs = 8



    @staticmethod
    def encrypt(keyfromaes):
        '''
        message de 32 octets
        '''
        #random_generator = Random.new().read
        #key = RSA.generate(1024, random_generator)
        #Public/private key pair
        key = RSA.generate(2048)
        print(type(key))
        print(key)
        print(key.can_encrypt())
        print(key.can_sign())
        print(key.has_private())
        public_key = key.publickey()
        enc_data = public_key.encrypt('abcdefgh', 32)


        #Encrypt
        """        
        msg = 'attack at dawn'
        pubkey = RSA.importKey(key.publickey().exportKey('DER'))
        privkey = RSA.importKey(key.exportKey('DER'))
        cipher = PKCS1_v1_5.new(pubkey)
        ciphertext = cipher.encrypt(msg)
        print(ciphertext)

        dcipher = PKCS1_v1_5.new(privkey)
        secret = dcipher.decrypt(ciphertext, 'thisIsForVerificationIfIAmRight')
        print(secret)
        """

    @staticmethod
    def create() :
        key = RSA.generate(2048)
        f = open('mykey.pem','w')
        f.write(key.exportKey('PEM'))
        f.close()

    @staticmethod
    def encrypt_RSA(public_key_loc, message):
        '''
        param: public_key_loc Path to public key
        param: message String to be encrypted
        return base64 encoded encrypted string
        '''

        key = open(public_key_loc, "r").read()
        rsakey = RSA.importKey(key)
        rsakey = PKCS1_OAEP.new(rsakey)
        encrypted = rsakey.encrypt(message)
        return encrypted.encode('base64')

    @staticmethod
    def decrypt_RSA(private_key_loc, package):
        '''
        param: public_key_loc Path to your private key
        param: package String to be decrypted
        return decrypted string
        '''
        key = open(private_key_loc, "r").read()
        rsakey = RSA.importKey(key)
        rsakey = PKCS1_OAEP.new(rsakey)
        decrypted = rsakey.decrypt(b64decode(package))
        return decrypted



      



