import os
import subprocess
import socket
from OpenSSL import SSL,crypto

from cryptography import x509
from cryptography.hazmat.backends.openssl import backend
from cryptography.x509.oid import AuthorityInformationAccessOID as authorityOID
from cryptography.x509.oid import ExtensionOID as extensionOID

# this method uses the pyOpenSSL and cryptography libraries to check the OCSP status of a host
def check_OCSP(host):
    certs = get_cert_chain(host)
    certp,chainp = dump_cert_chain(certs)
    cert = x509.load_pem_x509_certificate(certp, backend)
    uri = check_for_OCSP(cert)
    if not uri:
        print "No OCSP"
        return
    server = uri.split("/")[2]
    # write cert to file
    cert_file = "/tmp/cert.pem"
    chain_file = "/tmp/chain.pem"
    write_to_file(certp,cert_file)
    write_to_file(chainp,chain_file)

    output = subprocess.check_output(["openssl","ocsp","-CAfile","/etc/ssl/certs/ca-bundle.crt","-issuer",chain_file,"-cert",cert_file,"-url",uri,"-header","HOST",server])
    print output
    # first get signing cert
    # sign_file = "/tmp/signcert.pem"
    # with open(os.devnull, 'w') as devnull:
    #     openssl = subprocess.Popen(("openssl","ocsp","-issuer",chain_file,"-cert",cert_file,"-url",uri,"-header","HOST",server,"-resp_text"), stdout=subprocess.PIPE,stderr=devnull)
    #     sed = subprocess.check_output(("sed","-n","/-----BEGIN/,/-----END/p"),stdin=openssl.stdout)
    #     openssl.wait()
    #     write_to_file(sed,sign_file)

    #     output = subprocess.check_output(["openssl","ocsp","-VAfile",sign_file,"-issuer",chain_file,"-cert",cert_file,"-url",uri,"-header","HOST",server])
    lines = output.split("\n")
    if lines[0].split()[1] == "good":
        print "OK"
    else:
        print "BAD"

def write_to_file(text,filename):
    with open(filename,"w") as f:
        f.write(text)

def get_cert_chain(host):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host,443))
    client_ssl = SSL.Connection(SSL.Context(SSL.TLSv1_METHOD), client)
    client_ssl.set_connect_state()
    client_ssl.set_tlsext_host_name(host)
    client_ssl.do_handshake()
    chain = client_ssl.get_peer_cert_chain()
    client_ssl.close()
    return chain

def dump_cert_chain(certs):
    # convert to cryptography library x509 objects, since their implementation is more complete
    certp = crypto.dump_certificate(crypto.FILETYPE_PEM,certs[0])
    chainp = ''
    for cert in certs[1:]:
        chainp += crypto.dump_certificate(crypto.FILETYPE_PEM,cert)
    return certp,chainp

def check_for_OCSP(cert):
    ext = cert.extensions.get_extension_for_oid(extensionOID.AUTHORITY_INFORMATION_ACCESS)
    # print ext
    for access in ext.value:
        if access.access_method == authorityOID.OCSP:
            return access.access_location.value
    return ''

host = 'wikipedia.org'
print "Checking",host,"..."
check_OCSP(host)

host = 'www.google.com'
print "Checking",host,"..."
check_OCSP(host)


# Note: this gives errors. The response indicates the cert is good (and not revoked), but we can't validate the
# signature on the response.

# On Wikipedia:

# Response Verify Failure
# 140109156325240:error:27069065:OCSP routines:OCSP_basic_verify:certificate verify error:ocsp_vfy.c:126:Verify error:unable to get local issuer certificate

# On Google:

# WARNING: no nonce in response
# Response Verify Failure
# 140050032367480:error:27069076:OCSP routines:OCSP_basic_verify:signer certificate not found:ocsp_vfy.c:85:

# See this discussion
# http://serverfault.com/questions/686301/ocsp-responder-not-present

# I think they are doing it wrong -- this just fetches the cert and then tells OpenSSL to trust it. Won't work
# if there is a MiTM!

# I think the right way is to use the CAfile, but I'm not sure we have it set right

