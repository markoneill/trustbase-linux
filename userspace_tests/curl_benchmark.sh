#!/bin/bash

HOST=192.168.21.101
ITERATIONS=100

function get_it () {
	for ((i=0; i<$ITERATIONS; i++))
	do
	curl -w "@curl-format.txt" -o /dev/null --insecure -s "https://192.168.21.101:$2/$3_size.gar" >> "$3-$1"
	done
	return 0
}

function many_sizes () {
	get_it $1 $2 1000
	get_it $1 $2 10000
	get_it $1 $2 100000
	get_it $1 $2 1000000

	get_it $1 $2 10000000
	get_it $1 $2 100000000
#	get_it $1 $2 1000000000

#	get_it $1 $2 2000000000
}

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

#Benchmark Variables

OLD_DIR=$( /bin/pwd )
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TRUSTHUB_DIR=/home/jordan/trusthub-linux

#run a base test to google
#echo -e "\nTESTING WITHOUT TRUSTHUB:\n"
#many_sizes linux-vanilla.txt 4440

#insert trusthub
#cd $TRUSTHUB_DIR
#insmod $TRUSTHUB_DIR/trusthub_linux.ko th_path=\"$TRUSTHUB_DIR\"
#cd $OLD_DIR
#echo -e "\nMake sure sslsplit and the policy_engine are running:"
#echo `ps aux | grep sslsplit`
#echo `ps aux | grep policy_engine`

#run a test to accepted cert
#echo -e "\nTESTING GOOD CERT WITH TRUSHUB:\n"
many_sizes linux-vanilla.txt 4440

#run a test to proxied cert
#echo -e "\nTESTING BAD CERT WITH TRUSTHUB:\n"
#many_sizes linux-proxied.txt 4441

#remove trusthub
#echo -e "\nMake sure sslsplit and the policy_engine are still running:"
#echo `ps aux | grep sslsplit`
#echo `ps aux | grep policy_engine`

#rmmod trusthub_linux
#echo -e "\nREMOVED TRUSTHUB\n"
