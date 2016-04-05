#!/usr/bin/python
import dns.resolver
import hashlib
from trusthub_python import *

'''
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Cert. Usage  |   Selector    | Matching Type |               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               /
/                                                               /
/                 Certificate Association Data                  /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
https://tools.ietf.org/html/rfc6698
'''


class danePlugin(TrustHubPlugin):
    def _init_(self):
        pass
    
    def initialize(self):
        return INIT_SUCCESS
    
    def query(self, host, port, raw_certs):
        cert_chain = convert_tls_certificates_to_x509_list(raw_certs)
        print "Cert", cert_chain
        return checkDANE(self, host, port, "tcp", chain)
    
    def finalize():
        print "Python plugin finalized"
        return
        
    def getTLSARecord(self, hostname, port, protocol):
        answers = dns.resolver.query('_' + port + '._' + protocol + '.' + hostname, "TLSA")
        #signature = dns.resolver.query('_' + port + '._' + protocol + '.' + hostname, "RRSIG") # TODO check the signature to make sure this our real tlsa record

        #answers = dns.resolver.query('_%d._%s.%s' % port, protocol, hostname)
        return answers[0]

    def checkDANE(self, hostname, port, protocol, chain):
        record = getTLSARecord(hostname, port, protocol)
        toReturn = RESPONSE_INVALID # TODO should be watever abstain is
        if record.usage == 0:
            checkCA(chain, record)
        elif record.usage == 1:
            checkEnd(chain, record, True)
        elif record.usage == 2:
            checkAnchor(chain, record)
        elif record.usage == 3:
            checkEnd(chain, record, False)
        else:
            print '%d Certificate validation not supported' % record[0]
        return toReturn
    
    def checkCA(self, chain, record):
            # Check if any CA in the chain has this either 0 certificate or 1 public key
            for cert in chain[1:]:
                matched = match(getContent(cert, record.selector), record.cert, record.mtype)
                if matched:
                    return RESPONSE_VALID
            return RESPONSE_INVALID # TODO I think that only one of the CAs need to match it

    def checkEnd(self, chain, record, PKIX)
        # Check if the end certificate matches 0 certificate or 1 public key
        if not match(getContent(chain[0], record.selector), record.cert, record.mtype):
            return RESPONSE_INVALID
        if PKIX:
            #check PKIX validation
            pass
        return RESPONSE_VALID
    
    def checkAnchor(self, chain, record):
        # Check if matches either 0 certificate or 1 public key
        match(getContent(chain[-1], record.selector), record.cert, record.mtype)

    def getContent(self, cert, selector):
        if selector == 0:
            return crypto.dump_certificate(FILETYPE_ASN1, cert)
        elif selector == 1:
            return crypto.dump_publickey(FILETYPE_ASN1, cert.get_pubkey())
        assert False

    def match(self, content, tomatch, mType):
        if mType == 0:
            return content == tomatch
        elif mType == 1:
            return hashlib.sha256(content).hexdigest() == tomatch
        elif mType == 2:
            return hashlib.sha512(content).hexdigest() == tomatch
