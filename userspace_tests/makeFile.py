#!/usr/bin/python

import glob
import os

data = {}

for f in glob.glob("*-summary.csv"):
	amount = f[:f.find('-')]
	
	average = ""
	with open(f,"r") as fi:
		s = fi.read()
		average = s[s.find(',')+1:s.rfind(',')]
	
	if amount not in data:
		data[amount] = [None,None,None]
	if "vanilla" in f:
		data[amount][0] = average
	elif "accepted" in f:
		data[amount][1] = average
	elif "proxied" in f:
		data[amount][2] = average


#print the file
with open("table.csv", "w") as f:
	f.write("size,vanilla,accepted,proxied\r\n")
	for key in sorted(data):
		f.write(key +","+ data[key][0] +","+ data[key][1] +","+ data[key][2] +"\r\n")
