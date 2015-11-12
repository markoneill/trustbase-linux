#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

#Benchmark Variables
HOST=192.168.21.101
GOOD_PORT=4440
PROXY_PORT=4441
ITERATIONS=1024
FILE=/2000000_size.gar

PYTHON=python2.7.10

OLD_DIR=$( /bin/pwd )
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TRUSTHUB_DIR="$(cd "$DIR/../" && pwd )"

#run a base test to google
echo -e "\nTESTING WITHOUT TRUSTHUB:\n"
#$PYTHON $DIR/time_con.py -s $HOST -p $GOOD_PORT -i $ITERATIONS -o linux-vanilla -f $FILE

#insert trusthub
cd $TRUSTHUB_DIR
insmod $TRUSTHUB_DIR/trusthub_linux.ko th_path=\"$TRUSTHUB_DIR\"
cd $OLD_DIR
echo -e "\nMake sure sslsplit and the policy_engine are running:"
echo `ps aux | grep sslsplit`
echo `ps aux | grep policy_engine`

#run a test to accepted cert
#echo -e "\nTESTING GOOD CERT WITH TRUSHUB:\n"
$PYTHON $DIR/time_con.py -s $HOST -p $GOOD_PORT -i $ITERATIONS -o linux-trusthub-normal -f $FILE

#run a test to proxied cert
echo -e "\nTESTING BAD CERT WITH TRUSTHUB:\n"
#$PYTHON $DIR/time_con.py -s $HOST -p $PROXY_PORT -i $ITERATIONS -o linux-trusthub-proxied -f $FILE

#remove trusthub
echo -e "\nMake sure sslsplit and the policy_engine are still running:"
echo `ps aux | grep sslsplit`
echo `ps aux | grep policy_engine`

rmmod trusthub_linux
echo -e "\nREMOVED TRUSTHUB\n"
