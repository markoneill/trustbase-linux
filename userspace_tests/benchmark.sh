#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

#Benchmark Variables
HOST_GOOD="23.235.47.193"
HOST_PROXY="45.56.43.213"
HOST_GOOD_NAME="i.imgur.com"
HOST_PROXY_NAME="pma.phoenixteam.org"
HOST_GOOD_URI="/GVNm8JK.jpg"
HOST_PROXY_URI="/GVNm8JK.jpg"
PORT=443
ITERATIONS=1024

PYTHON=python2.7.10

OLD_DIR=$( /bin/pwd )
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TRUSTHUB_DIR="$(cd "$DIR/../" && pwd )"

#run a base test to google
echo -e "\nTESTING $HOST_GOOD_NAME WITHOUT TRUSTHUB:\n"
$PYTHON $DIR/time_con.py -s $HOST_GOOD -p $PORT -i $ITERATIONS -n $HOST_GOOD_NAME -o nontrusthub_google -f $HOST_GOOD_URI

#run a base test to pteam
echo -e "\nTESTING $HOST_PROXY_NAME WITHOUT TRUSTHUB:\n"
$PYTHON $DIR/time_con.py -s $HOST_PROXY -p $PORT -i $ITERATIONS -n $HOST_PROXY_NAME -o nontrusthub_phoenixteam -f $HOST_PROXY_URI

#insert trusthub
echo -e "\nINSERTING TRUSTHUB:\n"
cd $TRUSTHUB_DIR
insmod $TRUSTHUB_DIR/trusthub_linux.ko th_path=\"$TRUSTHUB_DIR\"
cd $OLD_DIR
echo -e "Make sure sslsplit and the policy_engine are running:"
echo `ps aux | grep sslsplit`
echo `ps aux | grep policy_engine`

#run a test to google
echo -e "\nTESTING $HOST_GOOD_NAME WITH:\n"
$PYTHON $DIR/time_con.py -s $HOST_GOOD -p $PORT -i $ITERATIONS -n $HOST_GOOD_NAME -o trusthub_google -f $HOST_GOOD_URI

#run a test to pteam
echo -e "\nTESTING $HOST_PROXY_NAME WITHOUT TRUSTHUB:\n"
$PYTHON $DIR/time_con.py -s $HOST_PROXY -p $PORT -i $ITERATIONS -n $HOST_PROXY_NAME -o trusthub_phoenixteam -f $HOST_PROXY_URI

#remove trusthub
echo -e "Make sure sslsplit and the policy_engine are still running:"
echo `ps aux | grep sslsplit`
echo `ps aux | grep policy_engine`

rmmod trusthub_linux
echo -e "\nREMOVED TRUSTHUB\n"
