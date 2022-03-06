from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
import base64
import time


#Derive Key
def increment_key(key):
	return key + "a"


def derive_key(key):
	ckdf = ConcatKDFHash(
		algorithm=hashes.SHA256(),
		length=32,
		otherinfo=None,
	)
	return ckdf.derive(key.encode())


def decrypt(data, key):
	key = derive_key(key)
	fernet = Fernet(base64.urlsafe_b64encode(key))
	data = fernet.decrypt(data)
	return data

#Variables
sourcePath = "test/SUPER SECRET.txt.ezenc"
destinationPath = "hahagettrolled.txt"
key = "a"


#Open File
try:
	with open(sourcePath, "br") as f:
		fileData = f.read()
except FileNotFoundError:
	print("Source file ", sourcePath, "not found")
	exit()

#Brute Force
startTime = time.time()
print("Begining Brute-Force at", startTime)
newData = None
while newData is None:
	try:
		newData = decrypt(fileData, key)
	except InvalidToken:
		key = increment_key(key)
endTime = time.time()
print("Brute-Force finished at ", time.time(), "("+str(endTime-startTime), "seconds)")
#Write to File
try:
	f = open(destinationPath, "xb")
except FileExistsError:
	print("File", destinationPath, "already exists.\nWould you like to overwrite?")
	if input("(y/n)").lower() == "y":
		try:
			f = open(destinationPath, "wb+")
		except:
			print("Fuck")
	else:
		print("File write cancelled.")
		exit()
f.write(newData)
f.close()
print("File output to", destinationPath)
