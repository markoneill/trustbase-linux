#!/usr/bin/python
from trusthub_python import *

class testPlugin(TrustHubPlugin):
    def _init_(self):
        pass
    
    def initialize(self):
        return INIT_SUCCESS
    
    def query(self, host, port, raw_certs):
        cert_chain = convert_tls_certificates_to_x509_list(raw_certs)
        return RESPONSE_VALID
    
    def finalize():
        return

myPlugin = testPlugin()
setPlugin(myPlugin)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

