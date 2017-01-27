#!/bin/bash

# Init
PM="/bin/yum" # Package Manager
CURDIR="$( pwd )"
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Force root
if [[ "$(id -u)" != "0" ]];
then
	echo "This script must be run as root" 1>&2
	exit -1
fi


# Required build libraries







$PM install openssl-devel libconfig-devel libnl3-devel libsqlite3x-devel libcap-devel python-devel kernel-devel-$(uname -r) kernel-headers-$(uname -r) libevent-devel pyOpenSSL


# Git submodules
git submodule init
git submodule update
cd $CURDIR/sslsplit
make
cd $CURDIR

# Make the files
cd $DIR
make && make install
cd $CURDIR

INSTALL_LOCATION=/usr/lib/trusthub-linux

# Start Trusthub
insmod $INSTALL_LOCATION/trusthub_linux.ko th_path="$INSTALL_LOCATION"
echo "Trusthub started"
