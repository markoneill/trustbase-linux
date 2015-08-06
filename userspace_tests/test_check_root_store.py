#!/usr/bin/python
# this script should take a hostname, grab it's certificate chain, then try to verify it against

import sys
import subprocess
import os.path
import re

from ctypes import cdll

program = "check_root_store"
temp_file = ".test_chain"
erase_temp_file = True
erase_shared_library = False
hostname = ""

def main():
	if len(sys.argv) < 2:
		print "USAGE : {0} some.webaddress.com [-f write/certs/here.pem] [-n custom.hostname.com]".format(sys.argv[0])
		sys.exit(1)
	
	hostname = sys.argv[1]
	
	expect = None
	for arg in sys.argv[2:]:
		if expect == None:
			if arg in ['-h', '-?', '--help', 'help']:
				print "USAGE : {0} some.webaddress.com [-f write/certs/here.pem] [-n custom.hostname.com]".format(sys.argv[0])
				sys.exit(1)
			if arg in ['-f', 'f', '--file', '-file']:
				expect = 'file'
			if arg in ['-n', 'n', '--host', '-host', '--hostname', '-hostname', '--name', '-name']:
				expect = 'hostname'
		elif expect == 'file':
			global temp_file, erase_temp_file
			temp_file = arg
			erase_temp_file = False
			print "Writing certificate chain to {0}".format(temp_file)
			expect = None
		elif expect == 'hostname':
			hostname = arg
			expect = None
	
	print "Using {0} as hostname".format(hostname)
	
	if not os.path.isfile(program + '.o'):
		print "{0} needs to see the shared library {1} in the current working directory.".format(sys.argv[0], program = '.o')
		print "Unable to find an executable '{0}'".format(program)
		if os.path.isfile(program +".c"):
			print "But found {0}.c, would you like to compile this to {0}?".format(program)
			response = raw_input("[y/N]")
			response = response.lower()
			if response != '' and not response.startswith('n'):
				p = subprocess.Popen("gcc -l crypto {0}.c -shared -fPIC -o {0}.o".format(program), shell=True)
				rc = p.wait()
				if rc != 0:
					print "Unable to compile {0}.c".format(program)
					sys.exit(1)
				else:
					erase_shared_library = True
			else:
				sys.exit(1)
		else:
			sys.exit(1)
	#make certificate file
	p = subprocess.Popen("openssl s_client -showcerts -connect {0}:443 </dev/null".format(sys.argv[1]), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	out, err = p.communicate()
	if p.returncode != 0:
		print "Invalid address"
		sys.exit(1)
	bg = "-----BEGIN CERTIFICATE-----"
	ed = "-----END CERTIFICATE-----"
	front = 0
	with open(temp_file, 'w') as f:
		while True:
			front = out.find(bg)
			if front == -1:
				break
			back = out.find(ed)
			f.write(out[front:back+len(ed)])
			f.write(' \n')
			out = out[back+len(ed):]
	
	#test against program
	lib = cdll.LoadLibrary("./{0}.o".format(program))
	root_store = lib.make_new_root_store()
	stack = lib.pem_to_stack(temp_file)
	rc = lib.query_store(hostname, stack, root_store)
	
	if rc == -1:
		print "{0} returned an error".format(program)
	elif rc == 0:
		print "{0} found the certificate invalid for {1}".format(program, sys.argv[1])
	elif rc == 1:
		print "{0} found the certificate valid for {1}".format(program, sys.argv[1])
	elif rc == 2:
		print "{0} had no opinion about the certificate for {1}".format(program, sys.argv[1])

	if erase_temp_file:
		os.remove(temp_file)
	sys.exit()


if __name__=="__main__":
	main()
