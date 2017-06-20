#!/usr/bin/python
import logging
logging.basicConfig(filename='example.log',level=logging.DEBUG)
import sys
def temp_errlog(exctype, value, tb):
    log.warning('My Error Information')
    log.warning('Type: '+ str(exctype))
    log.warning('Value: '+ str(value))
    log.warning('Traceback:'+ str(tb))

import os


sys.path.append(os.path.dirname(sys.path[0]))
from trustbase_python import *
import socks
import socket
import ssl
from OpenSSL import crypto
import json
import hashlib
import time
import random


random.seed(time.time())


class NotaryPlugin(TrustbasePlugin):
    config_file = "./notaries.cfg"
    
    def _init_(self):
        pass
    
    def initialize(self):
	# load the config file
        self.config_file = os.path.join(sys.path[0], self.config_file)
	self.known_notaries = self.loadConfig()
        return INIT_SUCCESS
    
    def query(self, host, port, raw_certs):
        cert_chain = convert_tls_certificates_to_x509_list(raw_certs)
        # hash the leaf cert
        cert_hash = cert_chain[0].digest("sha256")
        # choose a random one to be the proxy
        proxy = random.choice(self.known_notaries)
        # get responses
        responses = []
        for n in self.known_notaries:
            responses.append(self.runQuery(n['Address'],n['QueryPort'],proxy['Address'],proxy['ProxyPort'], '/home/jordan/trustbase-linux/policy-engine/plugins/notary_plugin/trusted_notaries.pem', host, port, cert_hash))
        print "responses", responses
        # congress the group
        return RESPONSE_VALID
    
    def finalize():
        return

    def loadConfig(self):
        instring = ""
        with open(self.config_file, 'r') as f:
	    for line in f:
	        if line.startswith('#'):
		    continue
                instring += line
	return json.loads(instring)

    def runQuery(self, host, port, p_addr, p_port, trusted_root, qhost, qport, qhash):
        try:
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS4, p_addr, p_port)
            print "set proxy"
            s.connect((host, port))
            # change CERT_NONE to CERT_REQUIRED, and check the cert against the known 
            print "connected"
            ss = ssl.wrap_socket(s, server_side=False, cert_reqs=ssl.CERT_REQUIRED, ca_certs=trusted_root, ssl_version=ssl.PROTOCOL_SSLv23)
            print "wrapped"
            ss.sendall("{};{};{}\n".format(qhash.strip(),qhost.strip(),qport))
            print "sent"
            print ss.recv(4096)
        except socks.ProxyConnectionError:
            print "Could not connect to socks proxy at {}:{}".format(p_addr, p_port)
        except ssl.SSLError:
            print "SSLError connecting to {}:{}".format(HOST, PORT)
            s.close()
        except socket.error:
            print "Socket Error"


myPlugin = NotaryPlugin()
setPlugin(myPlugin)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
