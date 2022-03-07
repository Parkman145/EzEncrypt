from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
import base64
import time
import string


letters = string.printable

#Switch Char
def switchchar(text, index):
	text = list(text)
	if abs(index) > len(text):
		text = letters[0] * abs(index)
		print("Current text length:", len(text))
		print("Current index:", index)
	else:
		if text[index] == letters[-1]:
			text[index] = letters[0]
			text = switchchar(text, index - 1)
		else:
			character = letters[letters.index(text[index])+1]
			text[index] = character
	return "".join(text)



#Switch Char (unicode)
def switchcharuni(text, index):
	text = list(text)
	if abs(index) > len(text):
		text = [chr(0)] * abs(index)
		print("Current text length:", len(text))
		print("Current index:", index)
	else:
		try:
			if ord(text[index]) == 55295:
				text[index] = chr(0)
				text = switchcharuni(text, index - 1)
			else:
				character = chr(ord(text[index])+1)
				text[index] = character
		except IndexError:
			print(text)
			print(index)
			print(len(text))
			print(ord(text[index]) == 55295)
			exit()
	return "".join(text)


#Derive Key
def increment_text(inpText):
	return inpText + "a"


def derive_key(rawkey):
	ckdf = ConcatKDFHash(
		algorithm=hashes.SHA256(),
		length=32,
		otherinfo=None,
	)
	return ckdf.derive(rawkey.encode())


def decrypt(data, decryptkey):
	decryptkey = derive_key(decryptkey)
	fernet = Fernet(base64.urlsafe_b64encode(decryptkey))
	data = fernet.decrypt(data)
	return data


#Variables
sourcePath = "test/SUPER SECRET.txt.ezenc"
destinationPath = "test/hahagettrolled.txt"
key = letters[0]


#Open File
try:
	with open(sourcePath, "br") as f:
		fileData = f.read()
except FileNotFoundError:
	print("Source file ", sourcePath, "not found")
	exit()

#Brute Force
startTime = time.time()
print("Beginning Brute-Force at", startTime)
newData = None
guesses = 0
while newData is None:
	try:
		newData = decrypt(fileData, key)
	except InvalidToken:
		key = switchchar(key, -1)
	except UnicodeEncodeError:
		print(ord(key[-1]))
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
