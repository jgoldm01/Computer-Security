#!/usr/bin/python

'''see supportingMaterial.txt for more documentation'''

import sys
import getopt
import math

# generates private and public keys given two primes
def generate(args, isString):
	assertLength(args, 2, "generate")
	p1 = int(args[0])
	p2 = int(args[1])
	n = p1*p2
	e = 3
	phi = (p1-1)*(p2-1)
	while phi%e == 0:
		e += 2
	if e > phi:
		print "gimme larger numbers. I can handle it"
		sys.exit(0)

	d = 1;
	while ((d*e) % phi) != 1:
		d += 1
	
	print "remember, your above two arguments must be primes for the rest to work! \n" \
				"in addition, n must be bigger than the message you intend to encrypt\n" \
				"public keys: modulus value n =", n, ", exponent e =", e, "\n"  \
				"private key: exponent d =", d

# encrypts message 
def encrypt(args, isString):
	assertLength(args, 3, "encrypt")
	try:
		m = int(args[0])
	except:
		m = 0;
		for char in args[0]:
			m *= 256;
			m += ord(char)
		# print "integer form of string message: ", m
	n = int(args[1])
	e = int(args[2])
	c = (m**e)%n


	print "encrypted message:", c


# decrypts message, prints as string if isString is true
def decrypt(args, isString):
	assertLength(args, 3, "decrypt")
	c = int(args[0])
	n = int(args[1])
	d = int(args[2])
	m = (c**d)%n
	# print "integer decrypted message:", m 

	if isString:
		string = ""
		while m >= 1:
			asc = m%256
			string += chr(asc)
			m /= 256
		string = string[::-1]
		print "decrypted message:", string
	else:
		print "decrypted message:", m

# evalues that the number of arguments is correct
def assertLength(args, argNum, flag):
	if len(args) != argNum:
		if flag == "generate":
			print "incorrect argument number, please provide two primes as arguments"
		elif flag == "encrypt":
			print "incorrect number of arguments, please provide three arguments: a message, " \
						"an exponent, and a modulus value"
		elif flag == "decrypt":
			print "incorrect number of arguments, please provide three integers: " \
						" cyphertext, exponent, and modulus value"
		sys.exit(0)



def main():
	isString = False;
	fun = generate;
	opts, args = getopt.getopt(sys.argv[1:], "geds", ["generate=", "encrypt=", "decrypt=", "string"])

	# print opts, args
	for o, a in opts:
		if o == "-g":
			fun = generate
		elif o == "-e":
			fun = encrypt 
		elif o == "-d":
			fun = decrypt
		elif o == "-s":
			isString = True

	fun(args, isString)



if __name__ == "__main__":
	main()