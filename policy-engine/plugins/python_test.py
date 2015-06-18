from OpenSSL import crypto
import sys
import traceback

root_store_file = "/etc/ssl/certs/ca-bundle.crt"

try:
	with open(root_store_file) as ROOT_STORE_FILE:
		chain = ROOT_STORE_FILE.read()
	
	delim = "-----BEGIN CERTIFICATE-----"
	root_certs = [delim+cert for cert in chain.split(delim) if cert]

	root_store = crypto.X509Store()

	for cert in root_certs:
		x509 = root_store.load_certificate(crypto.FILETYPE_PEM, cert)
		root_store.add_cert(x509)

except:
	throw ImportError("Error in attempting to read root store file and create \
						X509 Root Store in Memory")
	sys.exit(1)

def query(host, cert_chain):

	try:
		print "Checking...\nHost: %s\nCert Chain: %s\n\n" % (host, cert_chain)

		#construct x509 cert structure, store, and context from cert_chain
		cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_chain)
		store = crypto.X509Store()
		store_ctx = crypto.X509StoreContext(store, cert)

		#add cert to store
		store.add_cert(cert)

		try:
			store_ctx.verify_certificate()
			print "Certificate Chain verified!"
			is_valid = True
		except crypto.X509StoreContextError as (message, certificate):
			print "Error:", message
			print "Caused by certificate:", certificate
			is_valid = False

	except Exception as e:
		traceback.print_exc(file=sys.stderr)
		is_valid = False

	# logic for determining whether cert is valid

	return is_valid

