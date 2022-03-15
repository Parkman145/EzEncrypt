import getpass
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
import base64
import argparse
import os


#Derive Key
def derive_key(key):

	ckdf = ConcatKDFHash(
		algorithm=hashes.SHA256(),
		length=32,
		otherinfo=None,
	)
	return ckdf.derive(key.encode())


def encrypt_mode(data, key):

	fernet = Fernet(base64.urlsafe_b64encode(key))
	data = fernet.encrypt(data)
	return data


def decrypt_mode(data, key, console_output=False):
	fernet = Fernet(base64.urlsafe_b64encode(key))
	try:
		data = fernet.decrypt(data)
	except InvalidToken:
		print("Invalid Token")
		exit()
	if console_output:
		try:
			print(data.decode())
			exit()
		except UnicodeDecodeError:
			print("Error: Cannot print binary file to console.")
			exit()
	else:
		return data


def append_mode(data, key, text):
	fernet = Fernet(base64.urlsafe_b64encode(key))
	try:
		data = fernet.decrypt(data).decode()
	except InvalidToken:
		print("Invalid Token")
		exit()
	except UnicodeDecodeError:
		print("Invalid Text Encoding")
		exit()
	data = data + "\n" + text
	return fernet.encrypt(data.encode())


class C:
	pass


if __name__ == "__main__":
	c = C()
	parser = argparse.ArgumentParser(description='Encrypt/Decrypt files.')

	#Mode
	modeGroup = parser.add_subparsers(dest="mode", required=True)

	#Encrypt Mode
	encryptMode = modeGroup.add_parser("e", help="Encrypt file")
	encryptMode.add_argument("source", metavar="Source", help="Source Path", action="store")
	encryptMode.add_argument("-f", metavar="Destination", help="Write to custom file.")


	#Decrypt Mode
	decryptMode = modeGroup.add_parser("d", help="Decrypt file")
	decryptMode.add_argument("source", metavar="Source", help="Source Path", action="store")
	decryptMode.add_argument("-f", metavar="Destination", help="Write to custom file.")
	decryptMode.add_argument("-t", help="Print output to console. Will disable file output.", action="store_true")


	#Append Mode
	appendMode = modeGroup.add_parser("a", help="Append text to encrypted file")
	appendMode.add_argument("source", metavar="Source", help="Source Path", action="store")
	appendMode.add_argument("text", metavar="Text", help="Text To Append", action="store")
	appendMode.add_argument("-f", metavar="Destination", help="Write to custom file.")


	parser.parse_args(namespace=c)


	sourcePath = c.source

	#Derive Key

	#Open File
	try:
		with open(sourcePath, "br") as f:
			fileData = f.read()
	except FileNotFoundError:
		print("Source file ", sourcePath, "not found")
		exit()

	key = getpass.getpass()
	encKey = derive_key(key)
	match c.mode:
		case "e":
			newData = encrypt_mode(fileData, encKey)
		case "d":
			newData = decrypt_mode(fileData, encKey, console_output=c.t)
		case "a":
			newData = append_mode(fileData, encKey, c.text)
	if c.f is None:
		match c.mode:
			case "e":
				destinationPath = sourcePath + ".ezenc"
			case "d":
				if sourcePath.endswith(".ezenc"):
					destinationPath = sourcePath[:-6]
				else:
					destinationPath = os.path.splitext(sourcePath)[0] + "[DECRYPTED]" + os.path.splitext(sourcePath)[1]
			case "a":
				destinationPath = c.source
	else:
		destinationPath = c.f


	#Write to File
	print(c.source)
	try:
		f = open(destinationPath, "xb")
	except FileExistsError:
		print("File {} already exists.\nWould you like to overwrite?".format(destinationPath))
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
