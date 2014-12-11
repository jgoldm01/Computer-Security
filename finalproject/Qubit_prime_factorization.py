#!/usr/bin/python

'''calculates the prime factors of any number using the qubit class. 
	 it simulates how one could use qubits to determine prime factors of 
	 a number. However, because this is a classical computer, the qubit
	 values are random, rather than superimposed, which does not speed 
	 up the processing. 
'''

from qubit import Qubit
import sys
import math

def solve(num):
	if isPrime(num):
		print "prime factor:", num
		return

	# the maximum possile smallest factor of any number is its square root
	maxVal = num**.5
	#we need 2^maxVal qubits
	qubitNum = int(math.ceil(math.log(maxVal, 2)))

	qubits = [];
	qubitVals = [];
	for x in range(qubitNum):
		qubits.append(Qubit())
		qubitVals.append(0)

	
	isHorizMeasurement = 1
	while True:
		measure_qubits(qubits, qubitVals, isHorizMeasurement)
		testFactor = calcValue(qubitVals)

		#if testFactor is a factor, then check if it is prime. 
		#if the factor is not prime, call solve on both testFactor and num/testFactor
		if testFactor > 1:
			if num%testFactor == 0:
				if isPrime(testFactor):
					print "prime factor:", testFactor
					solve(num/testFactor)
					return
				else:
					solve(testFactor)
					solve(num/testFactor)
					return

		isHorizMeasurement ^= 1
		# print qubitVals, testFactor


# examines the values of the qubits
def measure_qubits(qubits, qubitVals, isHorizMeasurement):
	if isHorizMeasurement:
		for x in range(len(qubits)):
			qubitVals[x] = qubits[x].examine("horizontal_spin")
	else:
		for x in range(len(qubits)):
			qubitVals[x] = qubits[x].examine("polarization")

# transforms the values of the qubits into an integer
def calcValue(qubitVals):
	val = 0 
	for v in qubitVals:
		val *= 2
		val += v
	return val+1

#returns whether argument is a prime
def isPrime(num):
	if num < 2:
		return False
	if num == 2:
		return True
	if not num%2: 
		return False
	for x in range (3, int(math.sqrt(num))+1, 2):
		if num%x == 0:
			return False
	return True

#first checks if the number is prime, then calls recursive solve function
def main():
	num = int(sys.argv[1])
	if num < 2:
		print "give a number larger than 1"
	elif isPrime(num):
		print "number is prime!"
		return
	else:
		# the maximum possile smallest factor of any number is its square root
		maxVal = num**.5
		#we need 2^maxVal qubits
		qubitNum = int(math.ceil(math.log(maxVal, 2)))
		print "number of qubits required to solve this problem:", qubitNum
		solve(num)

if __name__ == "__main__":
	main()