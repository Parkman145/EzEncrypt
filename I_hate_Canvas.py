import requests
from pyDes import *
import hashlib
import getpass
import time

SECRET_HASH = "9b2a0477cf781b58fb341da7cdfd57914e142eb3792d3e284cd83ffdacf9c664"

with open("key", "br") as f:
	encryptedKey = f.read()

ciphertext = None

while 1:
	encKey = getpass.getpass("Password: ").encode("utf-8")
	if hashlib.sha256(encKey).hexdigest() != SECRET_HASH:
		print("Incorrect Encryption Key.",flush=True)
		time.sleep(0.1)
		continue

	ciphertext = triple_des(encKey).decrypt(encryptedKey, padmode=2)
	break

print("Key:", ciphertext.decode('utf-8'))
