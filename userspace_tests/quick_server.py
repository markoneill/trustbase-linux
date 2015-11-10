#!/usr/bin/python


import socket, ssl
import argparse

def deal_with_client(connstream):
    #data = connstream.read(1024)
    # finished with client
    data = connstream.recv(1024) 
    if data:
        connstream.send("Z"*int(data)) 
        print "Sent {0} bytes of data".format(data)

def main():
    #parse the args
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", nargs=1, required=True, type=int, help="The port to for listening", dest="port")
    parser.add_argument("-k", "--ssl-key", nargs=1, required=True, type=str, help="The ssl private key for the server", dest="key")
    parser.add_argument("-c", "--ssl-cert", nargs=1, required=True, type=str, help="The ssl public certificate for the server", dest="cert")
    args = parser.parse_args()

    #load the file
    host = '' 
    backlog = 5 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    time_start = 0
    time_end = 0

    s.bind((host,args.port[0])) 
    s.listen(backlog) 
    while 1:
        try:
            client, address = s.accept()
            connstream = ssl.wrap_socket(client, server_side=True, ssl_version=ssl.PROTOCOL_TLSv1, keyfile=args.key[0], certfile=args.cert[0])
            connstream.do_handshake()
            try:
                deal_with_client(connstream)
            except Exception as e:
                print "Data Error\n",e
            finally:
                connstream.close()
        except Exception as e:
            print "Connection Error\n",e
    s.shutdown(socket.SHUT_RDWR)
    time_end = time.time()
    s.close()

if __name__ == "__main__":
    main()


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
