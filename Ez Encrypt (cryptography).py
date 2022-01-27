#import hashlib
import getpass
import time
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
import base64

mode = sys.argv[1]
key = sys.argv[2]
sourcePath = sys.argv[3]
destinationPath = sys.argv[4]

ckdf = ConcatKDFHash(
    algorithm=hashes.SHA256(),
    length=32,
    otherinfo=None,
)
encKey = ckdf.derive(key.encode())

print(1)
with open(sourcePath, "br") as f:
	fileData = f.read()
print(2)
fernet = Fernet(base64.urlsafe_b64encode(encKey))
if (mode == 'encrypt'):
	print(2)
	newData = fernet.encrypt(fileData)
	print(2)
elif (mode == 'decrypt'):
	newData = fernet.decrypt(fileData)
else:
	raise Exception("Invalid Mode")
print(3)
try:
	f = open(destinationPath, "wxb")
except:
	print("File", destinationPath, "already exists.\nWould you like to overwrite?")
	if (input("(y/n)").lower() == "y"):
		try:
			f = open(destinationPath, "wb+")
		except:
			print("Fuck")
	else:
		print("File write cancelled.")
		exit()
print(4)
f.write(newData)
print(5)
f.close()
print(6)
print("File output to", destinationPath)