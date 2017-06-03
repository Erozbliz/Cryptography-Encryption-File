### main.py
import os
import time
import timeit
import moduletest

#hash officel
import hashlib

#pure AES
import aes

#import lib chilkat
import sys
from lib.chilkat import chilkat

#import lib pycrypto
from Crypto.Cipher import AES

#lib cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

#hash
from Crypto.Hash import SHA512
from Crypto.Hash import SHA
from Crypto.Hash import MD5

import aesCipherPycrypto
import aesCipherPycryptoECB
import desCipherPycrypto
import des3CipherPycrypto
import rsaPublicKeyPycrypto
import rsaPublicKeyChilkat

#Pour l'authentification corrrespond a sha3_512(bonjour123456)
PASSWORDAUTHENTIFICATION = "541da2acbf1ffd94294aeb4a6493b7a2de5fcf9bae77c2e5519c8f507bbb98d828cc2458f083e1d4ee37df353fb9d59a26785f262f43986de30b54e85d93a522"

#******************
# HASH
#******************

#HASH avec lib officiel
def hash():
	mystring = "Voici un message"
	print(hashlib.md5(mystring.encode('utf-8')).hexdigest())
	print(hashlib.sha1(mystring.encode('utf-8')).hexdigest())
	print(hashlib.sha3_512(mystring.encode('utf-8')).hexdigest())


def hashSHA3_512(msg):
	'''
	SHA3_512 autre solution a la suite des possibilités d'attaques contre les standards MD5, SHA-0 et SHA-1.
	Utilise Keccak fonction eponge
	'''
	bytemsg = msg.encode('utf-8')
	hashmsg = hashlib.sha3_512(bytemsg).hexdigest()
	print(hashmsg)

#Avec pycrypto
def hashSHA_512(msg):
	'''
	SHA-512 appartient a la famille SHA-2 de hachages cryptographiques. 
	Il produit le digest de 512 bits d'un message.
	Taille de bloc est de 1024 bits (et non 512 bits)
	'''
	h = SHA512.new()
	h.update(bytes(msg, encoding='utf-8'))
	print(h.hexdigest())

def hashSHA1(msg):
	'''
	SHA-1 produit le digest (le hash) de 160 bits (20 octets) d'un message.
	Cet algorithme n'est pas considere comme sur
	'''
	h = SHA.new()
	h.update(bytes(msg, encoding='utf-8'))
	print(h.hexdigest())

def hashMD5(msg):
	'''
	MD5 produit le digest (le hash) de 128 bits (16 octets) d'un message.
	Cet algorithme n'est pas considere comme sur
	'''
	h = MD5.new()
	h.update(bytes(msg, encoding='utf-8'))
	print(h.hexdigest())


#************************
# Encyption Symetrique
#************************

#AES pour message
def aesTest():
	mykey = "iliketrains"
	myMessage = "Voici mon message AES"
	
	cipher = aes.AESCipher(key=mykey)
	encrypted = cipher.encrypt(myMessage)
	print('##### AES encrypted , ',myMessage)
	print(encrypted)
	new_cipher = aes.AESCipher(key=mykey)
	decrypted = new_cipher.decrypt(encrypted)
	print('##### AES de crypted')
	print(decrypted)

#Tutoriel pycrypto
#http://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/
def encrypt_file(in_filename, out_filename, chunk_size, key, iv):
    des3 = DES3.new(key, DES3.MODE_CFB, iv)

    with open(in_filename, 'r') as in_file:
        with open(out_filename, 'w') as out_file:
            while True:
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                out_file.write(des3.encrypt(chunk))

def decrypt_file(in_filename, out_filename, chunk_size, key, iv):
    des3 = DES3.new(key, DES3.MODE_CFB, iv)

    with open(in_filename, 'r') as in_file:
        with open(out_filename, 'w') as out_file:
            while True:
                chunk = in_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                out_file.write(des3.decrypt(chunk))


#TEST 
def classTest():
	print(moduletest.choix)
	cfc = moduletest.Crypto()
	cfc.printdetails()


#AES Encrypte un fichier et decrypte un fichier avec Chilkat
def aesChilkat():
	print('Encrypte un fichier et decrypte un fichier ')
	nameOfFile= "canada_timelapse.mp4"
	extension = nameOfFile.split(".")[1]
	print('extension',extension)
	crypt = chilkat.CkCrypt2()

	#  Any string argument automatically begins the 30-day trial.
	success = crypt.UnlockComponent("30-day trial")
	if (success != True):
	    print(crypt.lastErrorText())
	    sys.exit()

	crypt.put_CryptAlgorithm("aes")

	#  CipherMode may be "ecb" or "cbc"
	crypt.put_CipherMode("cbc")

	#  KeyLength may be 128, 192, 256
	crypt.put_KeyLength(256)

	#  The padding scheme determines the contents of the bytes
	#  that are added to pad the result to a multiple of the
	#  encryption algorithm's block size.  AES has a block
	#  size of 16 bytes, so encrypted output is always
	#  a multiple of 16.
	crypt.put_PaddingScheme(0)

	#  An initialization vector is required if using CBC mode.
	#  ECB mode does not use an IV.
	#  The length of the IV is equal to the algorithm's block size.
	#  It is NOT equal to the length of the key.
	ivHex = "000102030405060708090A0B0C0D0E0F"
	crypt.SetEncodedIV(ivHex,"hex")

	#  The secret key must equal the size of the key.  For
	#  256-bit encryption, the binary secret key is 32 bytes.
	#  For 128-bit encryption, the binary secret key is 16 bytes.
	keyHex = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
	crypt.SetEncodedKey(keyHex,"hex")

	#  Encrypt a file, producing the .aes as output.
	#  The input file is unchanged, the output .aes contains the encrypted
	#  contents of the input file.

	#  Note: The .aes output file has no file format.  It is simply a stream
	#  of bytes that resembles random binary data.
	inFile = "fichier_a_encrypter/"+nameOfFile
	outFile = "fichier_a_encrypter/"+nameOfFile+".aes"
	success = crypt.CkEncryptFile(inFile,outFile)
	if (success != True):
	    print(crypt.lastErrorText())
	    sys.exit()

	#  For demonstration purposes, a different instance of the object will be used
	#  for decryption.
	decrypt = chilkat.CkCrypt2()

	#  All settings must match to be able to decrypt:
	decrypt.put_CryptAlgorithm("aes")
	decrypt.put_CipherMode("cbc")
	decrypt.put_KeyLength(256)
	decrypt.put_PaddingScheme(0)
	decrypt.SetEncodedIV(ivHex,"hex")
	decrypt.SetEncodedKey(keyHex,"hex")

	#  Decrypt the .aes
	#inFile = "fichier_a_encrypter/bonjour.pdf.aes"
	inFile = "fichier_a_encrypter/"+nameOfFile+".aes"
	outFile = "fichier_a_encrypter/recovered."+extension
	success = decrypt.CkDecryptFile(inFile,outFile)
	if (success == False):
	    print(decrypt.lastErrorText())
	    sys.exit()

	print("Cryptage et Decryptage OK")

#FERBNET Methode de fernet
def fernet() :
	key = Fernet.generate_key()
	f = Fernet(key)
	token = f.encrypt(b"my deep dark secret")
	msgdecrypt = f.decrypt(token)
	print(msgdecrypt)

#AES Faire attention à la taille
def aesCryptographyio() :
	backend = default_backend()
	key = os.urandom(32)
	iv = os.urandom(16)
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	encryptor = cipher.encryptor()
	ct = encryptor.update(b"a secret message") + encryptor.finalize()
	print(ct)
	decryptor = cipher.decryptor()
	myvar = decryptor.update(ct) + decryptor.finalize()
	print(myvar)

#AES
def aesWithFile() :
	file = open("to_enc.txt", "rb")
	data = file.read() # if you only wanted to read 512 bytes, do .read(512)
	obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
	message = "The answer is no"
	ciphertext = obj.encrypt(message)
	print(type(ciphertext))
	print(ciphertext)
	file_aes = open('testfile.byte','wb') 
	file_aes.write(ciphertext)
	file_aes.close()

#AES permet d avoir un message de n importe quelle taille
def aesAvecPaddingV1() :
	cipher = aesCipherPycrypto.AESCipher(key='sqdfq5sd4v89qz41s2x1vr5s4dgocj65')
	encrypted = cipher.encrypt("Hello World Hello World Hello World Hello World Hello World Hello World")
	print(encrypted)

	new_cipher = aesCipherPycrypto.AESCipher(key='sqdfq5sd4v89qz41s2x1vr5s4dgocj65')
	decrypted = new_cipher.decrypt(encrypted)
	print(decrypted)

#AES bloc CBC avec fichier video
def aesAvecPaddingV2() :
	"""
	Cryptage AES, Rijndael
	Peut utiliser n'importe quelle taille de donnees et taille de mot de passe grace au padding
	On manipule en octet pour garantir l'integrite des donnees
	Taille(s) du bloc       : 128 bits (16 octets)
	Longueur(s) de la clef  : 128(16), 192(24), 256(32) bits(octets)
	Nombre de tours         : 10,12,14 selon la taille de la clef
	Utilisation de : CBC Cipher Block Chaining. Les blocs sont liees entre eux.
	"""
	#avec un fichier
	#clef de 256 bit (32)
	cipherB = aesCipherPycrypto.AESCipher(key='sqdfq5sd4v89qz41s2x1vr5s4dgocj65')
	#open file
	file = open("fichier_a_encrypter/canada_timelapse.mp4", "rb")
	data = file.read() 
	encryptedB = cipherB.encrypt(data)

	faes = open("fichier_a_encrypter/canada_timelapse.aes", "w")
	faes.write(encryptedB)
	faes.close()

	new_cipherB = aesCipherPycrypto.AESCipher(key='sqdfq5sd4v89qz41s2x1vr5s4dgocj65')
	decrypted = new_cipherB.decryptByte(encryptedB)

	#create file
	f = open("fichier_a_encrypter/canada_timelapseDecrypt.mp4", "wb")
	f.write(decrypted)
	f.close()
	print('Ok')

def aesAvecPaddingECBV2() :
	"""
	Cryptage AES, Rijndael
	Peut utiliser n'importe quelle taille de donnees et taille de mot de passe grace au padding
	On manipule en octet pour garantir l'integrite des donnees
	Taille(s) du bloc       : 128 bits (16 octets)
	Longueur(s) de la clef  : 128(16), 192(24), 256(32) bits(octets)
	Nombre de tours         : 10,12,14 selon la taille de la clef
	Utilisation de ECB : Les blocs sont chiffrés indépendamment bloc par bloc
	"""
	#avec un fichier
	#clef de 256 bit (32)
	cipherB = aesCipherPycryptoECB.AESCipher(key='sqdfq5sd4v89qz41s2x1vr5s4dgocj65')
	#open file
	file = open("fichier_a_encrypter/canada_timelapse.mp4", "rb")
	data = file.read() 
	encryptedB = cipherB.encrypt(data)

	faes = open("fichier_a_encrypter/canada_timelapse.aes", "w")
	faes.write(encryptedB)
	faes.close()

	new_cipherB = aesCipherPycryptoECB.AESCipher(key='sqdfq5sd4v89qz41s2x1vr5s4dgocj65')
	decrypted = new_cipherB.decryptByte(encryptedB)

	#create file
	f = open("fichier_a_encrypter/canada_timelapseDecrypt.mp4", "wb")
	f.write(decrypted)
	f.close()
	print('Ok')

#DES
def DES() :
	#taille de 8 octects (64 bits)
	cipher = desCipherPycrypto.DESCipher(key='12345678')
	encrypted = cipher.encrypt("Hello World Hello World Hello World Hello World Hello World Hello World")
	print(encrypted)

	new_cipher = desCipherPycrypto.DESCipher(key='12345678')
	decrypted = new_cipher.decrypt(encrypted)
	print(decrypted)

#DES avec fichier video
def DESV2() :
	"""
	Data Encryption Standard (DES)
	DES est cryptographiquement securise, mais sa longueur cle est trop courte
	DES est vulnerable au bruteforce
	Taille(s) du bloc       : 64 bits (8)
	Longueur(s) de la cle   : 56 bits (7) + 8 bits de parite (1)
	Nombre de tours 16 tours du DES
	"""
	#taille de 8 octects (64 bits)
	#avec un fichier
	cipherB = desCipherPycrypto.DESCipher(key='12345678')
	#open file
	file = open("fichier_a_encrypter/canada_timelapse.mp4", "rb")
	data = file.read()
	encryptedB = cipherB.encrypt(data)

	faes = open("fichier_a_encrypter/canada_timelapse.des", "w")
	faes.write(encryptedB)
	faes.close()

	new_cipherB = desCipherPycrypto.DESCipher(key='12345678')
	decrypted = new_cipherB.decryptByte(encryptedB)

	#create file
	f = open("fichier_a_encrypter/canada_timelapseDecrypt.mp4", "wb")
	f.write(decrypted)
	f.close()
	print('Ok')

#3DES
def TDES() :
	"""
	Triple DES (Data Encryption Standard)
	Enchaine 3 applications successives de l'algorithme DES sur le meme bloc de donnees de 64 bits, avec 2 ou 3 clef DES differentes.
	Le TDES est cryptographiquement securise, il n'est ni aussi sur ni aussi rapide que AES.
	Taille(s) du bloc       : 64 bits (8 octets)
	Longueur(s) de la cle   : 168(21)ou 112(14) bits
	Nombre de tours 3x16 tours du DES
	"""
	cipher = des3CipherPycrypto.TDESCipher(key='voici une clef de 21 oct')
	encrypted = cipher.encrypt("Hello World Hello World Hello World Hello World Hello World Hello World")
	print(encrypted)

	new_cipher = des3CipherPycrypto.TDESCipher(key='voici une clef de 21 oct')
	decrypted = new_cipher.decrypt(encrypted)
	print(decrypted)

#3DES avec fichier video
def TDESV2() :
	"""
	Triple DES (Data Encryption Standard)
	Enchaine 3 applications successives de l'algorithme DES sur le meme bloc de donnees de 64 bits, avec 2 ou 3 clef DES differentes.
	Le TDES est cryptographiquement securise, il n'est ni aussi sur ni aussi rapide que AES.
	Taille(s) du bloc       : 64 bits (8 octets)
	Longueur(s) de la cle   : 168(21)ou 112(14) bits
	Nombre de tours 3x16 tours du DES
	"""
	#taille de 21 octects (168 bits)
	#avec un fichier
	cipherB = des3CipherPycrypto.TDESCipher(key='voici une clef de 21 oct')
	#open file
	file = open("fichier_a_encrypter/canada_timelapse.mp4", "rb")
	data = file.read()
	encryptedB = cipherB.encrypt(data)

	faes = open("fichier_a_encrypter/canada_timelapse.des", "w")
	faes.write(encryptedB)
	faes.close()

	new_cipherB = des3CipherPycrypto.TDESCipher(key='voici une clef de 21 oct')
	decrypted = new_cipherB.decryptByte(encryptedB)

	#create file
	f = open("fichier_a_encrypter/canada_timelapseDecrypt.mp4", "wb")
	f.write(decrypted)
	f.close()
	print('Ok')


#************************
# Encyption Asymetrique
#************************

#RSA NOT WORKING
def rsaPublicKeyV1(keyfromaes) :
	obj = rsaPublicKeyPycrypto.RSAPublicKey()
	#obj.encrypt(keyfromaes=keyfromaes)
	#obj.encrypt(keyfromaes)

#RSA WORKING
def rsaPublicKeyChilkatV1(keyfromaes) :
	rsaPublicKeyChilkat.rsaChilkat(keyfromaes)
	#rsaPublicKeyChilkat.generatePublicAndPrivateKey()


#************************
# Signature 
#************************

def md5_file(f, block_size=2**20):
	"""
	valider l'integrite des donnees echangees.
	Return un string md5
	"""
	md55 = hashlib.md5()
	name = "fichier_a_encrypter/"+f
	file = open(name, "rb")
	#dataaa = file.read()
	while True:
		data = file.read(block_size)
		if not data:
			break
		md55.update(data)
	return md55.hexdigest()


#************************
# PERFORMANCE
#************************

#PERFORMANCE encyption symetrique
def performanceSymmetricEncryption() :
	print("\nDES")
	t = time.process_time()
	DESV2()
	elapsed_time = time.process_time() - t
	print(elapsed_time)

	print("\n3DES")
	t = time.process_time()
	TDESV2()
	elapsed_time = time.process_time() - t
	print(elapsed_time)

	print("\nAES CBC")
	t = time.process_time()
	aesAvecPaddingV2()
	elapsed_time = time.process_time() - t
	print(elapsed_time)

	print("\nAES ECB")
	t = time.process_time()
	aesAvecPaddingECBV2()
	elapsed_time = time.process_time() - t
	print(elapsed_time)


#PERFORMANCE hashage
def performanceHash(msg) :
	print("\n SHA3_512")
	t = time.process_time()
	for x in range(0, 10000):
		bytemsg = msg.encode('utf-8')
		hashmsg = hashlib.sha3_512(bytemsg).hexdigest()
	elapsed_time = time.process_time() - t
	print(elapsed_time)


	print("\n SHA2_512")
	t = time.process_time()
	for x in range(0, 10000):
		h = SHA512.new()
		h.update(bytes(msg, encoding='utf-8'))
	elapsed_time = time.process_time() - t
	print(elapsed_time)

	print("\n SHA1")
	t = time.process_time()
	for x in range(0, 10000):
		h = SHA.new()
		h.update(bytes(msg, encoding='utf-8'))
	elapsed_time = time.process_time() - t
	print(elapsed_time)

	print("\n MD5")
	t = time.process_time()
	for x in range(0, 10000):
		h = MD5.new()
		h.update(bytes(msg, encoding='utf-8'))
	elapsed_time = time.process_time() - t
	print(elapsed_time)

#PERFORMANCE hashage
def performanceHashOff(msg) :
	print("empty")





#************************
# Authentification
#************************
def authentification(password) :
	bytepwd = password.encode('utf-8')
	hashpwd = hashlib.sha3_512(bytepwd).hexdigest()
	#print(PASSWORDAUTHENTIFICATION)
	#print(hashpwd)
	if(hashpwd==PASSWORDAUTHENTIFICATION) :
		return True
	else :
		return False


def genereSha3(msg) :
	bytepwd = msg.encode('utf-8')
	hashpwd = hashlib.sha3_512(bytepwd).hexdigest()
	return hashpwd



# MAIN
def main():
	#hash()
	#aesTest()
	#classTest()
	#aesTest()
	#fernet()
	#aesCryptographyio()
	#aesWithFile()

	#------------------------------
	"""
	msg = "cryptographic hash algorithm"
	hashSHA_512(msg)
	hashSHA1(msg)
	hashMD5(msg)
	hashSHA3_512(msg)
	"""

	#------------------------------

	#--AES Fonctionne 
	#aesAvecPaddingV1()
	#--AES Fonctionne sans commentaire (pour fichier lourd ex : video)
	#aesAvecPaddingV2()
	#aesAvecPaddingECBV2()

	#--DES Fonctionne 
	#DES()
	#--DES Fonctionne sans commentaire (pour fichier lourd ex : video) 
	#DESV2()

	#--3DES Fonctionne 
	#TDES()
	#--3DES Fonctionne sans commentaire (pour fichier lourd ex : video) 
	#TDESV2()

	#------------------------------

	#RSA, NOT WORKING
	#rsaPublicKeyV1("sqdfq5sd4v89qz41s2x1vr5s4dgocj65")

	#RSA, working
	#rsaPublicKeyChilkatV1("sqdfq5sd4v89qz41s2x1vr5s4dgocj65")

	#------------------------------
	#mypassword= "bonjour123456"
	#print(genereSha3(mypassword))

	#PERFORMANCE
	#performanceSymmetricEncryption()
	#performanceHash(msg)

	#------------------------------
	#print('Veuillez vous authentifier (=bonjour123456)')
	#mypassword = input('Entrez votre mot de passe: ')
	#booleanvar = authentification(mypassword)
	authentificationRSA = True
	#authentification via des certificats avec RSA
	if(authentificationRSA==True) :
		print('Authentification via des certificats avec RSA')
		print('Bonjour M')
		print('\n performanceHash')
		msg = "cryptographic hash algorithm"
		performanceHash(msg)
		print('\n performanceSymmetricEncryption')
		performanceSymmetricEncryption()
		print('\n RSA (regarder les fichiers .xml generes pour la clef publique et privee)')
		rsaPublicKeyChilkatV1("sqdfq5sd4v89qz41s2x1vr5s4dgocj65")

		print('\n Signature et verification')
		filetest1 = md5_file("canada_timelapse.mp4")
		filetest2 = md5_file("canada_timelapseDecrypt.mp4")
		print('Empreinte fichier original : ',filetest1)
		print('Empreinte fichier decrypte : ',filetest2)
		if(filetest1==filetest2) :
			print('OK : Fichier identique')
		else :
			print('Fichier non identique')

	else :
		print('Mot de passe faux')
	




main()