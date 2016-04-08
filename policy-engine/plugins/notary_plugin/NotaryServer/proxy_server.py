from twisted.internet.protocol import Protocol
from twisted.protocols.policies import TimeoutMixin
from twisted.protocols.socks import SOCKSv4

class BounceProtocol(SOCKSv4):
	pass
