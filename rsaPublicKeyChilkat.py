import sys
from lib.chilkat import chilkat


def rsaChilkat(keyfromaes) :
    rsa = chilkat.CkRsa()

    success = rsa.UnlockComponent("Anything for 30-day trial")
    if (success != True):
        print("RSA component unlock failed")
        sys.exit()

    #  This example also generates the public and private
    #  keys to be used in the RSA encryption.
    #  Normally, you would generate a key pair once,
    #  and distribute the public key to your partner.
    #  Anything encrypted with the public key can be
    #  decrypted with the private key.  The reverse is
    #  also true: anything encrypted using the private
    #  key can be decrypted using the public key.

    #  Generate a 4096-bit key.  Chilkat RSA supports
    #  key sizes ranging from 512 bits to 4096 bits.
    success = rsa.GenerateKey(4096)
    if (success != True):
        print(rsa.lastErrorText())
        sys.exit()

    #  Keys are exported in XML format:
    publicKey = rsa.exportPublicKey()
    privateKey = rsa.exportPrivateKey()

    print("publicKey")
    #print(publicKey)
    f = open('publicKey.xml','w')
    f.write(publicKey)
    f.close()

    print("privateKey")
    #print(privateKey)
    f = open('privateKey.xml','w')
    f.write(privateKey)
    f.close()

    plainText = keyfromaes

    #  Start with a new RSA object to demonstrate that all we
    #  need are the keys previously exported:
    rsaEncryptor = chilkat.CkRsa()

    #  Encrypted output is always binary.  In this case, we want
    #  to encode the encrypted bytes in a printable string.
    #  Our choices are "hex", "base64", "url", "quoted-printable".
    rsaEncryptor.put_EncodingMode("hex")

    #  We'll encrypt with the public key and decrypt with the private
    #  key.  It's also possible to do the reverse.
    success = rsaEncryptor.ImportPublicKey(publicKey)

    usePrivateKey = False
    encryptedStr = rsaEncryptor.encryptStringENC(plainText,usePrivateKey)
    print("encrypted msg RSA 4096")
    print(encryptedStr)

    #  Now decrypt:
    rsaDecryptor = chilkat.CkRsa()

    rsaDecryptor.put_EncodingMode("hex")
    success = rsaDecryptor.ImportPrivateKey(privateKey)


    usePrivateKey = True
    decryptedStr = rsaDecryptor.decryptStringENC(encryptedStr,usePrivateKey)
    print("key")
    print(decryptedStr)


def generatePublicAndPrivateKey() :
    rsa = chilkat.CkRsa()

    success = rsa.UnlockComponent("Anything for 30-day trial")
    if (success != True):
        print(rsa.lastErrorText())
        sys.exit()

    #  Generate a 1024-bit key.  Chilkat RSA supports
    #  key sizes ranging from 512 bits to 4096 bits.
    #  Note: Starting in Chilkat v9.5.0.49, RSA key sizes can be up to 8192 bits.
    #  It takes a considerable amount of time and processing power to generate
    #  an 8192-bit key.
    success = rsa.GenerateKey(4096)
    if (success != True):
        print(rsa.lastErrorText())
        sys.exit()

    #  Keys are exported in XML format:
    publicKey = rsa.exportPublicKey()
    print("publicKey")
    #print(publicKey)
    f = open('publicKey.pem','w')
    f.write(publicKey)
    f.close()

    privateKey = rsa.exportPrivateKey()
    print("privateKey")
    #print(privateKey)
    f = open('privateKey.pem','w')
    f.write(privateKey)
    f.close()
