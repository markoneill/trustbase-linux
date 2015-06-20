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
		x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
		root_store.add_cert(x509)

except:
	raise ImportError("Error in attempting to read root store file and create X509 Root Store in Memory")
	sys.exit(1)

def getCertLength(bytes):
	index = 0
	x = 0
	for count in range(3):
		x <<= 8
		x |= bytes[index]
		index += 1
	return x

def validateCertificate(store, cert):
	is_valid = False
	try:
		store_ctx = crypto.X509StoreContext(store, cert)
		store_ctx.verify_certificate()
		print "Certificate Chain verified!"
		is_valid = True
	except crypto.X509StoreContextError as (message, certificate):
		print "Certificate Chain is invialid!", message
		print "\tCaused by certificate:", certificate
	return is_valid

def query(host, cert_chain):
	length_field_size = 3
	is_valid = False
	try:
		store = crypto.X509Store()
		certs = []
		chain_length = len(cert_chain)
		while chain_length:
			# get the length of next cert and decrement chain_length accordingly
			cert_len = getCertLength(cert_chain)
			cert_chain = cert_chain[length_field_size:]
			chain_length -= length_field_size

			# read certificate from byte array and decrement chain_length accordingly
			cert = crypto.load_certificate(crypto.FILETYPE_ASN1, str(cert_chain[0:cert_len]))
			cert_chain = cert_chain[cert_len:]
			chain_length -= cert_len

			# add certificate to list
			certs.append(cert)
			store.add_cert(cert)
			print cert.get_subject().get_components()


			#for cert in reversed(certs):
			if validateCertificate(store, cert):
				store.add_cert(cert)
			else:
				is_valid = False

	except Exception as e:
		traceback.print_exc(file=sys.stderr)
		is_valid = False

	# logic for determining whether cert is valid

	return is_valid

