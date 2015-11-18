#!/usr/bin/python

import csv
import sys
import StringIO

def getStats(times, filename):
	if None not in times:
		# Get statistics
		stats = ""
		# Average
		average = sum(times, 0.0) / len(times)
		#stats += "Average connection time was {0} sec".format(average) + "\n"
		# Variance
		variance = sum([(i-average)**2 for i in times], 0.0) / len(times)
		#stats += "with a Variance of {0} sec".format(variance) + "\n"
		# Standard Deviation
		std_deviation = variance**2
		#stats += "and a Standard Deviation of {0} sec".format(std_deviation) + "\n"
		stats = filename +","+ str(average) +","+ str(std_deviation)
		print stats
		# Make csv file
		csvfile = StringIO.StringIO()
		writer = csv.writer(csvfile, delimiter=',')
		writer.writerow(times)
		csv_str = csvfile.getvalue()
		csvfile.close()
		return (stats, csv_str)
	else:
		print "{0} of the connections had errors".format(times.count(None))
		return None

def main():
	s = ""
	with open(sys.argv[1], "r") as f:
		s = f.read()
	print s.split("\n")
	numbers = [ float(x) for x in s.strip().split("\n") ]
	stats, csv_crap = getStats(numbers, sys.argv[1])
	with open(sys.argv[1][:sys.argv[1].find('.')] + "-summary.csv", "w") as f:
		f.write(stats + "\r\n")
if __name__ == "__main__":
	main()
