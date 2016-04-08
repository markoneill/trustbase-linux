from twisted.protocols.policies import TimeoutMixin
from twisted.internet.ssl import DefaultOpenSSLContextFactory
from twisted.protocols.basic import LineReceiver
from twisted.python import log
from update_cache import updateCert
import ssl
import sqlite3

NOTARY_ERROR = -1
NOTARY_VALID = True
NOTARY_INVALID = False

class NotaryServer(LineReceiver):
	def __init__(self, cachefile):
		self.cachefile = cachefile
		self.delimiter = '\n'

	def connectionMade(self):
		log.msg("New connection from {}".format(self.transport.getPeer()))
		return

	#lines should all be of the format sha1_hash_of_cert;hostname;port
	def lineReceived(self, line):
		log.msg("{} sent to us {}".format(self.transport.getPeer(), line))
		# compare against the cache
		try:
			cert, host, port =  line.split(';')
			port = int(port)
		except ValueError:
			self.report(NOTARY_ERROR)
			return
		try:	
			conn = sqlite3.connect(self.cachefile)
			c = conn.cursor()
			c.execute('SELECT hash FROM cache_table WHERE host=? AND port=?;', (host, port))
			f_cert = c.fetchone()
			conn.close()
			if f_cert is None:
				pass
			elif f_cert[0] == cert:
				self.report(NOTARY_VALID)
				return
			elif updateCert(host, port) == cert:
				self.report(NOTARY_VALID)
				return
			else:
				self.report(NOTARY_INVALID)
				return
					
		except sqlite3.OperationalError:
			#No such table
			#That's alright, we will do an updateCert
			pass
				
		# if it isn't in there, try to get one from the server
		if updateCert(host, port) == cert:
			self.report(NOTARY_VALID)
			return
		else:
			self.report(NOTARY_INVALID)
			return

		# fingerprint it and compare
		
		return

	def report(self, is_valid):
		self.sendLine(str(int(is_valid)))
		log.msg("Sent " + str(int(is_valid)))
		#close connection
		self.transport.loseConnection()
		return
