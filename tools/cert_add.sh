#!/bin/bash

# This tool will dispense the Trusthub certificate into a few programs that use a private root store

# Check Command Arguments
if test "$#" -ne 1 || test "$1" = "-h"; then
	echo "usage: $0 /path/to/trusthub.pem"
	echo "This tool will attempt to add the Trusthub Certificate into a few root stores"
	exit 1
fi

if ! test -f "$1"; then
	echo "Error: File $1 does not exist, or is empty"
	exit 1
fi

if test "$(file -b $1)" != "PEM certificate"; then
	echo "Error: File $1 is not a PEM certificate"
	exit 1
fi

if test $EUID -ne 0; then
	echo "Error: This script must be run as root"
	exit 1
fi

# Make sure we have certutil
which certutil > /dev/null
if test $? -ne 0; then
	echo "Could not find certutil in path"
	read -p "Install it? [Y/n] " -n 1 -r
	echo
	if [[ ! $REPLY =~ ^[Yy]$ ]]; then
		echo "Exiting"
		exit 0
	fi
	which yum > /dev/null
	if test $? -ne 0; then
		echo "This script requires yum to install certutils"
		exit 1
	fi
	yum -y install nss-util
	which certutil
	if test $? -ne 0; then
		echo "Could not install certutils"
		exit 1
	fi
fi

# Firefox
# Check if we can find the Firefox root store for each user
for home_user in $(ls /home); do
	for db_store in $(find -L /home/$home_user/.mozilla -type f -name "cert*.db" -print 2>/dev/null); do
		certutil -A -d $(dirname $db_store) -i $1 -n "Trusthub Certificate" -t "C,,"
		if test $? -ne 0; then
			echo "Could not add certificate to $db_store"
		fi
	done
done

# Python Httplib2
# Note, this is just the default locations, and will probably not cover new environments
for ca_store in $(find -L /usr/lib/ -type f \( -name "cacerts.txt" -o -name "certs*.pem" \) -print 2>/dev/null); do
	# remove it if we already have a certificate in there
	sed -i '/# Start Trusthub Cert/,/# End Trusthub Cert/d' $ca_store
	# So we can remove the cert when it changes
	echo "# Start Trusthub Cert" >> $ca_store
	cat $1 >> $ca_store
	echo "# End Trusthub Cert" >> $ca_store
done

exit 0
