# Cryptography-Encryption-File
Design and evaluate a secure data interchange system <br/>
## USE
-Launch the command "python main.py"
-The password is "bonjour123456"

# Explanation
## Cryptage AES, Rijndael (Symmetric)
<br/> Peut utiliser n'importe quelle taille de donnees et taille de mot de passe grace au padding
<br/> On manipule en octet pour garantir l'integrite des donnees
<br/> Taille(s) du bloc       : 128 bits (16 octets)
<br/> Longueur(s) de la clef  : 128(16), 192(24), 256(32) bits(octets)
<br/> Nombre de tours         : 10,12,14 selon la taille de la clef
<br/> Utilisation de : CBC Cipher Block Chaining. Les blocs sont liees entre eux.
<br/> Utilisation de : ECB Les blocs sont chiffrés indépendamment bloc par bloc

## Triple DES (Data Encryption Standard) (Symmetric)
<br/>  Enchaine 3 applications successives de l'algorithme DES sur le meme bloc de donnees de 64 bits, avec 2 ou 3 clef DES differentes.
<br/>  Le TDES est cryptographiquement securise, il n'est ni aussi sur ni aussi rapide que AES.
<br/>  Taille(s) du bloc       : 64 bits (8 octets)
<br/>  Longueur(s) de la cle   : 168(21)ou 112(14) bits
<br/>  Nombre de tours 3x16 tours du DES
<br/>
## Data Encryption Standard (DES) (Symmetric)
<br/>  DES est cryptographiquement securise, mais sa longueur cle est trop courte
<br/>  DES est vulnerable au bruteforce
<br/>  Taille(s) du bloc       : 64 bits (8)
<br/>  Longueur(s) de la cle   : 56 bits (7) + 8 bits de parite (1)
<br/>  Nombre de tours 16 tours du DES

##  Hash function : 
- MD5(checksum), SHA1, SHA2_512, SHA3_512

## Benchmark :
-Encyption symetrique
-Fonction de hashage


## REQUIRED
-python 3
-PyCrypto
-The files (videos, documents) in the folder "file_a_encrypter"

## OTHER
-anaconda
-pip install cryptography
-Keywords : Python3 , AES, Block CBC, Block ECB, Encrypt, Decrypt, chilkat, RSA, DES, 3DES, MD5, SHA1, SHA2, SHA3

## Capture 
![alt tag](https://github.com/Erozbliz/Cryptography-Encryption-File/blob/master/CAPTURE1.JPG?raw=true)