#!/usr/bin/python

from trusthub_python import *

from ctypes import cdll
import subprocess
from OpenSSL import SSL,crypto

from cryptography import x509
from cryptography.hazmat.backends.openssl import backend
from cryptography.x509.oid import AuthorityInformationAccessOID as authorityOID
from cryptography.x509.oid import ExtensionOID as extensionOID
import StringIO
import os
import os.path
import sys
import select
import subprocess

class CRLSetPlugin(TrustHubPlugin):
    crlsetFilePath = "/tmp/crlset"
    crlsetVersionFilePath = '/tmp/crlset-verison'
    crlsetDumpFilePath = '/tmp/crlset-dump'

    crlsetLogFilePath = '/tmp/crlset.log'
    crlsetCertFilePath = '/tmp/crlset_cert.pem'
    crlsetChainFilePath = '/tmp/crlset_chain.pem'

    crlsetLibraryPath = os.path.dirname(os.path.realpath(__file__))+'/crlset.so'

    #this counter will invoke an CRLSet update after UPDATE_AT_COUNT number of TLS Connections
    connectionCounter = 0
    UPDATE_AT_COUNT = 100
    def _init_(self):
        pass
    
    def initialize(self):
        sys.stdout = Python_Plugin_Logger(self.crlsetLogFilePath)
        crlset_tools = cdll.LoadLibrary(self.crlsetLibraryPath)
        self.updateCrlSet(crlset_tools)
        print "CRLSet Revocation plugin initialized"
        return INIT_SUCCESS
    
    def query(self, host, port, cert_chain):
        crlset_tools = cdll.LoadLibrary(self.crlsetLibraryPath)
        self.connectionCounter += 1
        if self.connectionCounter >= self.UPDATE_AT_COUNT:
            self.updateCrlSet(crlset_tools)
            self.connectionCounter = 0

        certs = convert_tls_certificates_to_x509_list(cert_chain)
        self.write_to_files(certs)
        
        returnValue = self.isCertInCrlSet(crlset_tools, self.crlsetCertFilePath)
        print returnValue
        print "out"
        return RESPONSE_VALID

    def updateCrlSet(self, crlset_tools):
        doesFileExist = os.path.isfile(self.crlsetFilePath)
        if doesFileExist :
            verisonNumber = self.getCRLSetVerisonNumber()
            print "versionNumber Found " + verisonNumber
            crlset_tools.getCurrentVersionFromPython()
            newsetVerisonNumber = self.getCRLSetVerisonNumber()
            print "newsetVerisonNumber Found " + newsetVerisonNumber

            if verisonNumber == newsetVerisonNumber:
                return False
        else:
            crlset_tools.getCurrentVersionFromPython()

        print "crlset_tools.fetchFromPython()"
        didthiswork = crlset_tools.fetchFromPython()
        return True

    def getCRLSetVerisonNumber(self):
        verisonNumber = "-1"
        doesFileExist = os.path.isfile(self.crlsetVersionFilePath)
        if doesFileExist :
            with open(self.crlsetVersionFilePath,"r") as f:
                verisonNumber = f.read()
        return verisonNumber

    def isCertInCrlSet(self, crlset_tools, certFilename):
        successfulRead = crlset_tools.dumpFromPython(self.crlsetFilePath, certFilename)
        if successfulRead == False:
            print("Error: dumpFromPython failed")
            return RESPONSE_ABSTAIN

        content = ""
        doesFileExist = os.path.isfile(self.crlsetDumpFilePath)
        if doesFileExist :
            with open(self.crlsetDumpFilePath,"r") as f:
                content = f.read()
            if content != "":
                return RESPONSE_INVALID
        
        return RESPONSE_VALID

    def write_to_files(self,certs):
        root = crypto.dump_certificate(crypto.FILETYPE_PEM, certs[0])
        self.write_to_file(root,self.crlsetCertFilePath)
        certp = ''
        for cert in certs[1:]:
            certp += crypto.dump_certificate(crypto.FILETYPE_PEM,cert)
        self.write_to_file(certp,self.crlsetChainFilePath)

    def write_to_file(self,text,filename):
        with open(filename,"wb") as f:
            f.write(text)

    def finalize():
        print "Python plugin finalized"
        return

myPlugin = CRLSetPlugin()
setPlugin(myPlugin)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4


