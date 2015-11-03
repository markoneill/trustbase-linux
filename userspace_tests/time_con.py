#!/usr/bin/python

import time
import socket
import ssl
import argparse
import csv
import sys


def makeConnection(host, port, name, file_uri):
	t_start = time.time()
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		if name is None:
			s_wrapped = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv23)
		else:
			ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
			s_wrapped = ctx.wrap_socket(s, server_hostname=name)
		s_wrapped.connect((host, int(port)))
		t_handshake = time.time()
		if file_uri:
			# Send Get
			if name:
				request = "GET {0} HTTP/1.1\r\nhost:{1}\r\n\r\n".format(file_uri, name)
			else:
				request = "GET {0} HTTP/1.1\r\nhost:{1}\r\n\r\n".format(file_uri, host)
			try:
				s_wrapped.sendall(request)
			except Exception as e:
				print "Could not send data to {0}:{1} because {2}".format(host, port, e)
			# Receive file
			data = []
			while True:
				chunk = None
				chunk = s_wrapped.recv(4096)
				if not chunk:
					break
				data.append(chunk)
				#Check for end of jpg
				if chunk.endswith("\xff\xd9"):
					#this is the end of a jpg, probably.
					if len(''.join(data)) < 4337587:
						print "ERROR, MIGHT HAVE NOT GOTTEN ALL THE DATA"
						print "GOT", len(''.join(data))
					break
		s_wrapped.shutdown(socket.SHUT_RDWR)
		t_end = time.time()
		s_wrapped.close()
		return (t_handshake - t_start, t_end - t_start)
	except Exception as e:
		print "Could not connect to {0}:{1} because {2}".format(host, port, e)

def getStats(times, filename):
	if None not in times:
		# Get statistics
		stats = ""
		# Average
		average = sum(times, 0.0) / len(times)
		stats += "Average connection time was {0} sec".format(average) + "\n"
		# Variance
		variance = sum([(i-average)**2 for i in times], 0.0) / len(times)
		stats += "with a Variance of {0} sec".format(variance) + "\n"
		# Standard Deviation
		std_deviation = variance**2
		stats += "and a Standard Deviation of {0} sec".format(std_deviation) + "\n"

		print stats

		# Make csv file
		if filename:
			with open(filename + ".csv", 'wb') as csvfile:
				writer = csv.writer(csvfile, delimiter=',')
				writer.writerow(times)
			with open(filename + "_stats.txt", 'w') as f:
				f.write(stats)
				
	else:
		print "{0} of the connections had errors".format(times.count(None))

def main():
	#do argparse crap
	parser = argparse.ArgumentParser()
	parser.add_argument("-s", "--host", nargs=1, required=True, help="The TLS server address", dest="host")
	parser.add_argument("-p", "--port", nargs=1, type=int, required=True, help="Port the TLS server is running on", dest="port")
	parser.add_argument("-i", "--itrs", nargs=1, type=int, required=False, default=[9], help="The number of times to connect", dest="itrs")
	parser.add_argument("-n", "--name", nargs=1, required=False, help="The optional server name to send as an SNI", dest="name")
	parser.add_argument("-o", "--file", nargs=1, required=False, help="The optional filename prefix for writing the data", dest="file")
	parser.add_argument("-f", "--remote-file", nargs=1, required=False, help="A remote file to GET on the server, specified as a URI", dest="uri")
	args = parser.parse_args()
	
	ver = sys.version_info
	if (ver.minor < 7) or (ver.minor == 7 and ver.micro < 9):
		if args.name:
			args.name = None
			print "Warning: Server name not available until Python 2.7.9"
	if args.uri:
		if not args.uri[0].endswith(".jpg") and not args.uri[0].endswith(".jpeg"):
			print "Warning: This tool only works with geting .jpg images"
			return
	
	handshake_times = []
	full_times = []
	for i in xrange(1,args.itrs[0]+1):
		time = makeConnection(args.host[0], args.port[0], args.name[0] if args.name else None, args.uri[0] if args.uri else None)
		handshake_times.append(time[0])
		full_times.append(time[1])
		if None not in time:
			print "Connection {0} : Handshake {1} sec{2}".format(i, time[0], " : +Data {0} sec".format(time[1]) if args.uri else "")
	
	getStats(handshake_times, (args.file[0] + "_handshake_data") if args.file else None)
	if args.uri:
		getStats(full_times, (args.file[0] + "_full_data") if args.file else None)

if __name__ == "__main__":
	main()
