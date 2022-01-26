import requests
from pyDes import *
import hashlib
import getpass
import time

SECRET_HASH = "1bf69783a518693c79ad77c93f07237521c1aaf6c95b63b28af0ae6e033a6a2c"

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

print("Key:", ciphertext)
r = requests.get("https://sjusd.instructure.com/api/v1/courses/32313/activity_stream?access_token="+ciphertext.decode())
print(r.json)