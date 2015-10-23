#!/usr/bin/python

import time
import socket
import ssl
import argparse
import csv
import sys


def makeConnection(host, port, name):
	t_start = time.time()
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		if name is None:
			s_wrapped = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv23)
		else:
			ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
			s_wrapped = ctx.wrap_socket(s, server_hostname=name)
		s_wrapped.connect((host, int(port)))
		t_end = time.time()
		s_wrapped.shutdown(socket.SHUT_RDWR)
		s_wrapped.close()
		return t_end - t_start
	except Exception as e:
		print "Could not connect to {0}:{1} because {2}".format(host, port, e)

def main():
	#do argparse crap
	parser = argparse.ArgumentParser()
	parser.add_argument("-s", "--host", nargs=1, required=True, help="The TLS server address", dest="host")
	parser.add_argument("-p", "--port", nargs=1, type=int, required=True, help="Port the TLS server is running on", dest="port")
	parser.add_argument("-i", "--itrs", nargs=1, type=int, required=False, default=[9], help="The number of times to connect", dest="itrs")
	parser.add_argument("-n", "--name", nargs=1, required=False, help="The optional server name to send as an SNI", dest="name")
	parser.add_argument("-o", "--file", nargs=1, required=False, help="The optional csv filename for writing the data", dest="file")
	args = parser.parse_args()
	
	ver = sys.version_info
	if (ver.minor < 7) or (ver.minor == 7 and ver.micro < 9):
		if args.name:
			args.name = None
			print "Warning: Server name not available until Python 2.7.9"
	
	times = []
	for i in xrange(1,args.itrs[0]+1):
		time = makeConnection(args.host[0], args.port[0], args.name[0] if args.name else None)
		times.append(time)
		if time is not None:
			print "Connection {0} took {1} sec".format(i, time)
	
	if None not in times:
		# Get statistics
		# Average
		average = sum(times, 0.0) / len(times)
		print "Average connection time was {0} sec".format(average)
		# Variance
		variance = sum([(i-average)**2 for i in times], 0.0) / len(times)
		print "with a Variance of {0} sec".format(variance)
		# Standard Deviation
		std_deviation = variance**2
		print "and a Standard Deviation of {0} sec".format(std_deviation)

		# Make csv file
		if args.file:
			with open(args.file[0], 'wb') as csvfile:
				writer = csv.writer(csvfile, delimiter=',')
				writer.writerow(times)
	else:
		print "{0} of the connections had errors".format(times.count(None))

if __name__ == "__main__":
	main()
