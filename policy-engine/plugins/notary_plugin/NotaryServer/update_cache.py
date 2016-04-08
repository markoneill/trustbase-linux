from multiprocessing import Process
from twisted.python import log
import time, sched, datetime
import ssl
import sqlite3
from OpenSSL import crypto

cachefile = None

def updateCert(host, port):
	log.msg("Getting certificate from {}:{}".format(host,port))
	try:
		cert = ssl.get_server_certificate((host,port))
		#h = hashlib.sha1()
		#h.update(cert)
		#cert_hash = h.hexdigest()
		cert_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
		cert_hash = cert_obj.digest("sha256")
		#add or update the cache
		updateCache(cert_hash, host, port)
		#return the cert_hash
		return cert_hash
	except ssl.SSLError:
		log.msg("Could not get a certificate from {}:{}".format(host,port))
		return "0"
	
def updateCache(cert_hash, host, port):
	try:
		conn = sqlite3.connect(cachefile)
		c = conn.cursor()
		c.execute('CREATE TABLE IF NOT EXISTS cache_table (hash TEXT, host TEXT NOT NULL, port INTEGER NOT NULL, PRIMARY KEY ( host, port));')
		c.execute('INSERT OR REPLACE INTO cache_table VALUES(?, ?, ?);', (cert_hash, host, port))
		conn.commit()
		conn.close()
	except sqlite3.OperationalError:
		conn.rollback()
		conn.close()
		log.msg("Had an error trying to update the database")
	return

def runUpdate(s, s_time):
	# schedule update in 24 hours
	n_time = s_time + datetime.timedelta(days = 1)
	s.enterabs(time.mktime(n_time.utctimetuple()), 1, runUpdate, (cachefile, s, n_time))
	log.msg("Updating now at "+ datetime.datetime.now().strftime("%d/%b/%y at %X")+"--Next update at "+ n_time.strftime("%d/%b/%y at %X"))
	# update stuff
	
	try:
		conn = sqlite3.connect(cachefile)
		c = conn.cursor()
		# select all of the lines, to update their hash
		c.execute('SELECT * FROM cache_table;')
		results = c.fetchall()
		conn.close()
		for line in results:
			updateCert(line[1], line[2], cachefile)

	except sqlite3.OperationalError:
		log.msg("Had an error trying to update the database as the daemon")
	s.run()

def scheduleUpdate():
	#find next 1 in the morning
	s = sched.scheduler(time.time, time.sleep)
	n = datetime.datetime.today()
	n = n.replace(hour=1, minute=0, second=0)
	n = n + datetime.timedelta(days = 1)
	log.msg("Time is "+ datetime.datetime.now().strftime("%d/%b/%y at %X")+"--Next update at "+ n.strftime("%d/%b/%y at %X"))
	s_time = time.mktime(n.utctimetuple())
	s.enterabs(s_time, 1, runUpdate, (cachefile, s, n))
	s.run()
	log.msg("Quitting Updater");

def forkUpdater(cachefile_in):
	global cachefile
	cachefile = cachefile_in
	p = Process(target=scheduleUpdate)
	p.daemon = True
	p.start()
	return
