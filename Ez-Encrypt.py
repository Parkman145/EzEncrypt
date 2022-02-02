#import hashlib
import getpass
import time
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
import base64
import argparse


#Derive Key
def deriveKey(key):

	ckdf = ConcatKDFHash(
		algorithm=hashes.SHA256(),
		length=32,
		otherinfo=None,
	)
	return ckdf.derive(key.encode())

#Encrypt/Decrypt
def encrypt(mode, key, data):
	fernet = Fernet(base64.urlsafe_b64encode(key))
	if (mode == 'encrypt'):
		return fernet.encrypt(data)
	elif (mode == 'decrypt'):
		return fernet.decrypt(data)
	else:
		raise Exception("Invalid Mode")



class C:
	pass


if __name__ == "__main__":
	c = C()
	sourcePath = ""
	parser = argparse.ArgumentParser(description = 'Encrypt/Decrypt files.')

	#Mode
	parser.add_argument("mode", choices=["encrypt", "decrypt", "e", "d"], metavar = "Mode", action = "store") 
	outputGroup = parser.add_mutually_exclusive_group()


	#Flags
	outputGroup.add_argument("-t", help = "Print output to console. Will disable file output.", action = "store_true")

	#Paths
	parser.add_argument("source", metavar = "Source", help = "Source Path", action = "store")
	outputGroup.add_argument("-f", metavar = "Destination", help = "Write to custom file.")
	parser.parse_args(namespace=c)


	#Set Mode
	if (c.mode in ["e", "encrypt"]):
		mode = "encrypt"
	elif (c.mode in ["d", "decrypt"]):
		mode = "decrypt"
	else:
		raise Exception("Oh no")

	if (mode == "encrypt" and c.t == True):
		raise Exception("Text output cannot be used in encryption mode.")

	key = getpass.getpass()
	sourcePath = c.source

	#Derive Key
	encKey = deriveKey(key)






	#Open File
	try:
		with open(sourcePath, "br") as f:
			fileData = f.read()
	except FileNotFoundError:
		Print("Source file ", sourcePath, "not found")



	#Encrypt/Decrypt File Data
	try:
		newData = encrypt(mode, encKey, fileData)
	except:
		print("Incorect Key.")
		exit()


	if (c.t):
		try:
			print(newData.decode())
		except UnicodeDecodeError:
			print("Error: Cannot print binary file to console.")
			exit()
	else:
		if (c.f is None):
			if (mode == "encrypt"):
				destinationPath = sourcePath + ".ezenc"
			else:
				if (sourcePath.endswith(".ezenc")):
					destinationPath = sourcePath[:-6]

				else:
					destinationPath = os.path.splitext()[0]+"_decrypted"+os.path.splitext()[1]
		else:
			destinationPath = c.f
	#Write to File
		try:
			f = open(destinationPath, "xb")
		except FileExistsError:
			print("File", destinationPath, "already exists.\nWould you like to overwrite?")
			if (input("(y/n)").lower() == "y"):
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

