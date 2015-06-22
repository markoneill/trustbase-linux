from OpenSSL import crypto
import sys
import traceback

DEBUG = True
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

except Exception as e:
	traceback.print_exc(file=sys.stderr)
	print "Error in attempting to read root store file and create X509 Root Store in Memory"
	sys.exit(1)

def query(host, cert_chain):
	is_valid = False
	try:
		print "Checking cert for Host: %s" % (host)

		#parse certificates from chain string
		certs_X509 = convert_tls_certificates_to_x509_list(cert_chain);


		#make sure leaf cert matches host
		valid_names = get_subject_names(certs_X509[0])

		if DEBUG:
			print "--> Checking that host is in leaf node CN or alt subject names..."

		if not (host in valid_names or '*.' + '.'.join(host.split('.')[1:]) in valid_names):
			if DEBUG:
				print "neither %s nor %s are in %s" % (host, '*.' + '.'.join(host.split('.')[1:]), valid_names)

		else:
			if DEBUG:
				print "--> Checking the order of the cert chain..."
			#reorder the chain, if out of order
			ordered_chain = order(certs_X509)
			if ordered_chain:
				#reverse the ordered chain
				certs_X509 = ordered_chain[::-1]

				ca_cert = certs_X509[0]

				#check root store for trust of ca cert
				context = crypto.X509StoreContext(root_store, ca_cert)

				try:
					if DEBUG:
						print "--> Checking that each cert in chain has signed path to its neighbor..."

					# one by one, add next cert in chain if it's verified
					for cert in certs_X509:
						context = crypto.X509StoreContext(root_store, cert)
						context.verify_certificate()
						try:
							root_store.add_cert(cert)
						except:
							pass
					if DEBUG:
						print "--> Checking that all certs in chain have not expired..."

					# all certs are verified; now check expiration
					is_valid = validate_expiration(certs_X509)

				except crypto.X509StoreContextError as (message):
					print "Error:", message

	except Exception as e:
		traceback.print_exc(file=sys.stderr)
	
	if DEBUG:
		if is_valid:
			print "--> The Cert chain looks good for the given host!"
		else:
			print "--> Uh-oh, the cert chain doesn't look good for the given host :("

	return is_valid


def order(chain):
	ordered = []
	
	#assume leaf node is first
	ordered.append(chain[0])
	
	for i in xrange(1, len(chain)):
		prev = ordered[i-1]
		next = None
		
		for j in xrange(1, len(chain)):
			cand = chain[j]
			
			if link_is_valid(cand, prev) or j == len(chain)-1:
				next = cand
				break
		if next:
			ordered.append(next)
		else:
			# we can't determine correct order
			return False
	return ordered


def get_subject_names(cert):
	CN = cert.get_subject().commonName
	alt_names = get_names('subjectAltName', cert)
	alt_names.append(CN)
	return alt_names

def get_issuer_names(cert):
	CN = cert.get_issuer().commonName
	alt_names = get_names('issuerAltName', cert)
	alt_names.append(CN)
	return alt_names

def get_names(extension_name, cert):
	cert_extensions = [cert.get_extension(index) for index in xrange(cert.get_extension_count())]
	dns_strings = [str(e).split(',') for e in cert_extensions if e.get_short_name() == extension_name]
	
	if dns_strings:
		names = [dns.strip().replace('DNS:', '') for dns in dns_strings[0] if 'DNS:' in dns]
		return names
	else:
		return []
	
	

def link_is_valid(cand, prev):
	prev_cert_issuer_names = get_issuer_names(prev)
	cand_cert_subject_names = get_subject_names(cand)

	#just need one prev issuer name to be equal to cand subject name
	for issuer_name in prev_cert_issuer_names:
		for subject_name in cand_cert_subject_names:
			if issuer_name == subject_name:
				return True

	return False

def validate_expiration(certs):
	for cert in certs:
		if cert.has_expired():
			return False

	return True

def convert_tls_certificates_to_x509_list(cert_chain):
	length_field_size = 3
	certs = []
	chain_length = len(cert_chain)
	while chain_length:
		# get the length of next cert and decrement chain_length accordingly
		cert_len = get_cert_length_from_bytes(cert_chain)
		cert_chain = cert_chain[length_field_size:]
		chain_length -= length_field_size

		# read certificate from byte array and decrement chain_length accordingly
		cert = crypto.load_certificate(crypto.FILETYPE_ASN1, str(cert_chain[0:cert_len]))
		cert_chain = cert_chain[cert_len:]
		chain_length -= cert_len

		# add certificate to list
		certs.append(cert)
		print cert.get_subject().get_components()
	return certs

def get_cert_length_from_bytes(bytes):
        index = 0
        x = 0
        for count in range(3):
                x <<= 8
                x |= bytes[index]
                index += 1
        return x
