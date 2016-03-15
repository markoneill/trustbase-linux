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
    
    def query(self, host, certs):
        print "Revocation plugin queried"
        # I implemented this code in the Trusthub_python addon
        #self.write_to_file(cert_chain,'/tmp/certchain')
        #certs = self.convert_tls_certificates_to_x509_list(cert_chain)
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


    def convert_tls_certificates_to_x509_list(self,cert_chain):
        length_field_size = 3
        certs = []
        chain_length = len(cert_chain)
        while chain_length:
            # get the length of next cert and decrement chain_length accordingly
            cert_len = self.get_cert_length_from_bytes(cert_chain)
            cert_chain = cert_chain[length_field_size:]
            chain_length -= length_field_size

            # read certificate from byte array and decrement chain_length accordingly
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, str(cert_chain[0:cert_len]))
            cert_chain = cert_chain[cert_len:]
            chain_length -= cert_len

            # add certificate to list
            certs.append(cert)
        return certs

    def get_cert_length_from_bytes(self,bytes):
        index = 0
        x = 0
        for count in range(3):
            x <<= 8
            x |= bytes[index]
            index += 1
        return x

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


