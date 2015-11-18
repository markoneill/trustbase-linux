#!/usr/bin/python

import time
import socket
import ssl
import argparse
import csv
import sys
import StringIO

def getImage(s_wrapped, file_uri, name, host):
	if file_uri and s_wrapped:
		# Send Get
		if name:
			request = "GET {0} HTTP/1.1\r\nhost:{1}\r\n\r\n".format(file_uri, name)
		else:
			request = "GET {0} HTTP/1.1\r\nhost:{1}\r\n\r\n".format(file_uri, host)
		try:
			s_wrapped.sendall(request)
		except Exception as e:
			print "Could not send data to because {0}".format(e)
		# Receive file
		received = []
		while True:
			chunk = None
			chunk = s_wrapped.recv(4096)
			if not chunk:
				break
			received.append(chunk)
			if len(''.join(received)) >= 50000000:
				break
		return received

def getData(s_wrapped, data):
	#tell the server how much data we want
	print "getting data", str(data)
	request = str(data)
	s_wrapped.sendall(request)
	#receive data
	received = []
	while True:
		chunk = None
		chunk = s_wrapped.recv(4096)
		if not chunk:
			break
		received.append(chunk)
		#check for end
		if len(''.join(received)) >= data:
			break

def makeConnection(host, port, name, file_uri=None, data=None):
	t_start = time.time()
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((host, int(port)))
		t_tcp_handshake = time.time()
		if name is None:
			s_wrapped = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv23)
		else:
			ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
			s_wrapped = ctx.wrap_socket(s, server_hostname=name)
		s_wrapped.do_handshake()
		t_ssl_handshake = time.time()
		if file_uri:
			getImage(s_wrapped, file_uri, name, host)
		elif data:
			getData(s_wrapped, data)
		s_wrapped.shutdown(socket.SHUT_RDWR)
		t_end = time.time()
		s_wrapped.close()
		return (t_tcp_handshake - t_start, t_ssl_handshake - t_start, t_end - t_start)
	except Exception as e:
		print "Could not connect to {0}:{1} because {2}".format(host, port, e)

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
	#do argparse crap
	parser = argparse.ArgumentParser()
	parser.add_argument("-s", "--host", nargs=1, required=True, help="The TLS server address", dest="host")
	parser.add_argument("-p", "--port", nargs=1, type=int, required=True, help="Port the TLS server is running on", dest="port")
	parser.add_argument("-i", "--itrs", nargs=1, type=int, required=False, default=[9], help="The number of times to connect", dest="itrs")
	parser.add_argument("-n", "--name", nargs=1, required=False, help="The optional server name to send as an SNI", dest="name")
	parser.add_argument("-o", "--file", nargs=1, required=False, help="The filename prefix for writing the csv files", dest="file")
	parser.add_argument("-d", "--data", action='store_true', required=False, help="Test: a data receive from our test server", dest="data")
	parser.add_argument("-r", "--range", action='store_true', help="Test: a range test to our test server", dest="data_range")
	parser.add_argument("-f", "--remote-file", nargs=1, required=False, help="Test: a remote file to GET on the server, specified as a URI", dest="uri")
	args = parser.parse_args()
	
	#check the version
	ver = sys.version_info
	if (ver.minor < 7) or (ver.minor == 7 and ver.micro < 9):
		if args.name:
			args.name = None
			print "Warning: Server name not available until Python 2.7.9"

	#check the extention
	if args.uri:
		if args.data_range:
			print "-r is incompatable with -f or -d, ignoring..."
		else:
			if args.data:
				print "-d is incompatable with -f, ignoring..."
	
	if not args.data_range:
		#do a non range test
		tcp_times = []
		ssl_times = []
		data_times = []
		for i in xrange(1,args.itrs[0]+1):
			#make the connections
			ttime = makeConnection(args.host[0], args.port[0], args.name[0] if args.name else None, args.uri[0] if args.uri else None, 2000000 if args.data else None)
			tcp_times.append(ttime[0])
			ssl_times.append(ttime[1])
			data_times.append(ttime[2])
			if None not in ttime:
				print "Connection {0} : TCP Connect {1}s : TLS Connect {2}s{3}".format(i, ttime[0], ttime[1], " : +Data {0}s".format(ttime[2]))
			#wait a touch
			time.sleep(0.1)
		
		#gather the data
		tcp_line, tcp_data = getStats(tcp_times, "TCP Connect")
		ssl_line, ssl_data = getStats(ssl_times, "TLS Connect")
		if args.uri or args.data:
			data_line, data_data = getStats(data_times, "2MB Receive")
		
		#make the files
		if args.file:
			with open(args.file[0] + "-summary.csv", "w") as f:
				f.write(tcp_line + "\r\n")
				f.write(ssl_line + "\r\n")
				if args.uri or args.data:
					f.write(data_line + "\r\n")
				
			with open(args.file[0] + "-data.csv", "w") as f:
				#make Header
				f.write("Type")
				for i in xrange(1,args.itrs[0]+1):
					f.write(",Trial {0}".format(i))
				f.write("\r\n")
				#write data
				f.write("TCP Connect," + tcp_data + "\r\n")
				f.write("TLS Connect," + ssl_data + "\r\n")
				if args.uri or args.data:
					f.write("2MB Transfer," + data_data + "\r\n")
	else:
		#do a range test
		#we only care about the data part for this
		data_times = {}
		amount = 10
		while 1:
			round_times = []
			for i in xrange(1,args.itrs[0]+1):
				ttime = makeConnection(args.host[0], args.port[0], None, None, amount)	
				round_times.append(ttime[2])
				if None not in ttime:
					print "Connection {0} : {1} bytes : {2}s".format(i, amount, ttime[2])
			data_times[amount] = round_times
			if amount < 1000000:
				amount *= 2
			elif amount < 4000000:
				amount = 4000000
			else:
				break
		
		#gather the data
		
		#make the files
		if args.file:
			
			with open(args.file[0] + "-data.csv", "w") as f:
				#print header
				f.write("Bytes")
				for i in xrange(1,args.itrs[0]+1):
					f.write(",Trial {0}".format(i))
				f.write("\r\n")
				for key in data_times:
					f.write(str(key))
					for ttime in data_times[key]:
						f.write(",{0}".format(ttime))
					f.write("\r\n")
if __name__ == "__main__":
	main()
