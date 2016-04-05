#!/usr/bin/python
from trusthub_python import *

class testPlugin(TrustHubPlugin):
    def _init_(self):
        pass
    
    def initialize(self):
        print "Python plugin initialized"
        return INIT_SUCCESS
    
    def query(self, host, port, raw_certs):
        print "Python plugin queried"
        print "Host", host
        print "Port", port
        cert_chain = convert_tls_certificates_to_x509_list(raw_certs)
        print "Cert", cert_chain
        return RESPONSE_VALID
    
    def finalize():
        print "Python plugin finalized"
        return

myPlugin = testPlugin()
setPlugin(myPlugin)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

