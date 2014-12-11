#!/usr/bin/python

''' Qubit class: mimics properties of a qubit, for educational purposes.
		in examining the qubit, if the type of the measurement is the same as
		the last, then the qubit will not change its value. this simulates the 
		collapsing of the wave function. If the measurement is different, then
		the qubit outputs a random value
''' 


import random

class Qubit:
	def __init__ (self):
		self.randomize_values()
		self.lastMeasurement = "none"

	def examine(self, measurement):
		if self.lastMeasurement != measurement:
			self.randomize_values()
		self.lastMeasurement = measurement

		if measurement == "horizontal_spin":
			return self.horizontal_spin;
		elif measurement == "polarization":
			return self.polarization

	def randomize_values(self):
		self.horizontal_spin = random.randint(0,1)
		self.polarization = random.randint(0,1)

