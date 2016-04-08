#!/usr/bin/env python
from twisted.protocols.socks import SOCKSv4Factory
from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.ssl import DefaultOpenSSLContextFactory
from twisted.python.modules import getModule
from twisted.python import log
import sys
import ssl

from proxy_server import BounceProtocol
from notary_server import NotaryServer
from update_cache import forkUpdater 

cachefile = "cachefile.db"

# Each Notary can be a SOCKS proxy to the other notaries
# This Facorty handles the incoming proxy connections
class BounceFactory(SOCKSv4Factory):
	def buildProtocol(self, addr):
		#limit connection number here
		return BounceProtocol(None, reactor)

# This is the main Factory, for Notary duties
class NotaryFactory(Factory):
	def buildProtocol(self, addr):
		return NotaryServer(cachefile)

def main():
	log.startLogging(sys.stdout)

	# Start the daemon, to update the cache certificate fingerprints once a day
	forkUpdater(cachefile)
	# Start the Bounce Proxy Server
	reactor.listenTCP(6112, BounceFactory(None))
	# Start the Notary SSL server
	reactor.listenSSL(6113, NotaryFactory(), DefaultOpenSSLContextFactory("./testroot.key","./testroot.pem"), backlog=15)

	reactor.run()

if __name__ == "__main__":
    main()
