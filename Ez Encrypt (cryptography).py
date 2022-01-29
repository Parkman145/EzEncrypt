#import hashlib
import getpass
import time
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
import base64
import argparse

class C:
	pass

c = C()

parser = argparse.ArgumentParser(description = 'Encrypt/Decrypt files.')

#Mode
modeGroup = parser.add_mutually_exclusive_group(required=True)
#parser.add_argument("mode", choices=["encrypt", "decrypt", "e", "d"], metavar = "Mode", action = "store") 
#modeGroup.add_argument("encrypt", action = "store_const", help = "Encrpt file.")
#modeGroup.add_argument("decrypt", action = "store_true", help = "Decrypt file.")

#Flags
parser.add_argument("-t", metavar = "Print Output", help = "Print output to console. Will disable file output.", action = "store")

#Paths
parser.add_argument("source", metavar = "Source", help = "Source Path", action = "store")
parser.add_argument("destination", metavar = "Destination", help = "Destination Path. Defaults to source file path with .ezenc")
parser.parse_args(namespace=c)
#args = parser.parse_args()










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