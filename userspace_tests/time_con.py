#!/usr/bin/python

import time
import socket
import ssl
import argparse

def makeConnection(host, port, name):
	t_start = time.clock()
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
		s_wrapped = ctx.wrap_socket(s, server_hostname=name)
		s_wrapped.connect((host, int(port)))
		t_end = time.clock()
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
	args = parser.parse_args()
	
	
	times = []
	for i in xrange(1,args.itrs[0]+1):
		time = makeConnection(args.host[0], args.port[0], args.name[0] if args.name else None)
		times.append(time)
		print "Connection {0} took {1} sec".format(i, time)
	
	average = sum(times, 0.0) / len(times)
	print "Average connection time was {0} sec".format(average)

if __name__ == "__main__":
	main()
