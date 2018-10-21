#!/usr/bin/python

from argparse import ArgumentParser

def encrypt(key, input):
	if (len(input) % len(key) != 0):
		n = len(key) - len(input) % len(key)
		for i in range(n):
			input += " "

	h = []

	for a in range(len(key)):
		i = a
		for b in range(len(input)/len(key)):
			h.append(ord(input[i]) ^ ord(key[a]))
			i += len(key)

	encrypted = ""

	for j in range(len(h)):
		encrypted +="%02x" % h[j]

	return encrypted
	
def decrypt(key, input):
	input = input.decode('hex')
	h = []
	a = 0
	for i in range(len(key)):
		for j in range(len(input)/len(key)):
			h.append(ord(input[a]) ^ ord(key[i]))
			a += 1
			
	decrypted = ""
	
	for j in range(len(h)):
		decrypted += chr(h[j])
	
	decrypted2 = ""
	
	for i in range(len(input)/len(key)):
		for j in range(0, len(input), len(input)/len(key)):
			decrypted2 += decrypted[j+i]
			
	return decrypted2

def main():
	print """
   _____      _______    _____ _       _               
  / ____|  /\|__   __|  / ____(_)     | |              
 | (___   /  \  | |    | |     _ _ __ | |__   ___ _ __ 
  \___ \ / /\ \ | |    | |    | | '_ \| '_ \ / _ \ '__|
  ____) / ____ \| |    | |____| | |_) | | | |  __/ |   
 |_____/_/    \_\_|     \_____|_| .__/|_| |_|\___|_|   
                                | |                    
                                |_|                    
	"""
	argp = ArgumentParser(description="SAT Cipher", usage="./sat_cipher.py [options] [-k key] [-i text]")
	
	argp.add_argument('-k', dest='key', required=True, help='Key text')
	
	argp.add_argument('-i', dest='input', required=True, help='Input text')
	
	argp.add_argument('-e', dest='encrypt', action='store_true', help='Encrypt text with key')
	
	argp.add_argument('-d', dest='decrypt', action='store_true', help='Decrypt text with key')
	
	args = argp.parse_args()
	
	if args.encrypt and not args.decrypt:
		print "Plaintext\t:" , args.input
		print "Key\t\t:" , args.key
		print "Ciphertext\t:", encrypt(args.key, args.input)
		
	elif not args.encrypt and args.decrypt:
		print "Ciphertext\t:" , args.input
		print "Key\t\t:" , args.key
		print "Plaintext\t:", decrypt(args.key, args.input)
	
	
if __name__ == "__main__":
	main()