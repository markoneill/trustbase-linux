#!/usr/bin/python

from trusthub_python import *

from OpenSSL import SSL,crypto

from cryptography import x509
from cryptography.hazmat.backends.openssl import backend
from cryptography.x509.oid import AuthorityInformationAccessOID as authorityOID
from cryptography.x509.oid import ExtensionOID as extensionOID

import subprocess

class testPlugin(TrustHubPlugin):
    def _init_(self):
        pass
    
    def initialize(self):
        print "Revocation plugin initialized"
        return INIT_SUCCESS
    
    def query(self, host, port, cert_chain):
        print "Revocation plugin queried"
        self.write_to_file(cert_chain,'/tmp/certchain')
        certs = convert_tls_certificates_to_x509_list(cert_chain)
        self.write_to_files(certs)
        uri = self.check_for_OCSP(certs[0])
        print uri
        if not uri:
            print "No OCSP"
            return RESPONSE_ABSTAIN
        return self.validate_certs(uri)

    def validate_certs(self,uri):
        cert_file = "/tmp/cert.pem"
        chain_file = "/tmp/chain.pem"
        sign_file = "/tmp/signcert.pem"
        server = uri.split("/")[2]
        output = ""
        with open("/tmp/error.txt", 'w') as f:
            output = subprocess.check_output(["openssl","ocsp","-no_nonce","-CApath","/etc/ssl/certs","-CAfile","/etc/ssl/certs/ca-bundle.crt","-issuer",chain_file,"-cert",cert_file,"-VAfile",chain_file,"-url",uri,"-header","HOST",server,"-resp_text"],stderr=f)
        # check for error
        error = self.check_error()
        cert = None
        if error:
            cert = self.find_cert(output)
            if cert:
                self.write_to_file(cert,sign_file)
        tries = 5
        while error and cert and tries > 0:
            print "trying with signature..."
            with open("/tmp/error.txt", 'w') as f:
                output = subprocess.check_output(["openssl","ocsp","-CApath","/etc/ssl/certs","-CAfile","/etc/ssl/certs/ca-bundle.crt","-VAfile",sign_file,"-issuer",chain_file,"-cert",cert_file,"-url",uri,"-header","HOST",server,"-resp_text"],stderr=f)
            error = self.check_error()
            if error:
                tries -= 1
                cert = self.find_cert(output)
                if cert:
                    self.append_to_file(cert,sign_file)

        if tries == 0:
            print "BAD"
            return RESPONSE_INVALID
        else:
            return self.verify_output(output)

    def check_for_OCSP(self,cert):
        certp = crypto.dump_certificate(crypto.FILETYPE_PEM,cert)
        cert = x509.load_pem_x509_certificate(certp, backend)
        ext = cert.extensions.get_extension_for_oid(extensionOID.AUTHORITY_INFORMATION_ACCESS)
        for access in ext.value:
            if access.access_method == authorityOID.OCSP:
                return access.access_location.value
        return ''

    def check_error(self):
        error = False
        with open("/tmp/error.txt",'r') as f:
            if f.readline().strip() != "Response verify OK":
                error = True
        return error

    def find_cert(self,text):
        capture = False
        output = ""
        for line in text.split("\n"):
            if line == "-----BEGIN CERTIFICATE-----":
                capture = True
                output += line + "\n"
            elif line == "-----END CERTIFICATE-----":
                capture = False
                output += line + "\n"
            elif capture:
                output += line + "\n"

    def verify_output(self,text):
        for line in text.split("\n"):
            if line.startswith("/tmp/cert.pem:"):
                fields = line.split(" ")
                if fields[1] == "good":
                    print "OK"
                    return RESPONSE_VALID;
        print "BAD"
        return RESPONSE_INVALID;

    def write_to_files(self,certs):
        root = crypto.dump_certificate(crypto.FILETYPE_PEM, certs[0])
        self.write_to_file(root,'/tmp/cert.pem')
        certp = ''
        for cert in certs[1:]:
            certp += crypto.dump_certificate(crypto.FILETYPE_PEM,cert)
        self.write_to_file(certp,'/tmp/chain.pem')

    
    def write_to_file(self,text,filename):
        with open(filename,"wb") as f:
            f.write(text)

    def append_to_file(self,text,filename):
        with open(filename,"a") as f:
            f.write(text)

    def finalize():
        print "Python plugin finalized"
        return

myPlugin = testPlugin()
setPlugin(myPlugin)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4


