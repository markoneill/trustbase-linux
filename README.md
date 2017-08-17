# TrustBase - An OS service to repair and strengthen TLS certificate validation

## Overview

TrustBase is an operating system service that grants administrators strict controls over how all incoming TLS certificates are validated. It installs a loadable kernel module (LKM) that transparently captures TLS (and SSL) handshake messages sent between the local machine and a remote host. It then extracts certificate and other relevant information and validates them according to adminisrator preferences, as indicated by a configuration file. Administrators may install additional "plugins", services that perform additional or replacement certificate validation, and also control how validation decisions from these plugins are aggregated.

## Compatibility

TrustBase on Linux is primarily built for newer (v4.5+) kernels but should be functional on many previous versions. It has been tested on Fedora 26 and may need some minor adjustments to work with other distributions and versions. Continued development will focus on stability, debian and redhat packaging, and general ease of use.

## Compilation

Cloning the repository and running 

	make

should sufficiently compile all relevant binaries for both the LKM as well as supporting userspace daemons. Currently the makefile is not as general as it could be for each distro of Linux, and will be rewritten to utilize ldconfig in the future (pull requests welcome!)

## Installation

Running

	./installer.sh

will place compiled binaries and configuration in system directories. It will also compile TrustBase.

## Removal

Running

	rmmod trusbase

as a privileged user will remove the TrustBase LKM and shut down all userspace daemons.

## Configuration

The TrustBase configuration file is located at /etc/trustbase.cfg by default. This file uses the libconfig syntax and contains three major sections: addons, plugins, and aggregation settings.

The addons section is an array of installed addons and their corresponding information. Addons provide language support for plugins to be written in other languages. You do not need to modify this section unless you plan on installing addons. The name and description fields of an addon entry can be administrator chosen, and serve to distinguish the addon from others. The type field specifies the string that plugins that use this addon for support should use when identifying their own type field. The path field is the path to the addon shared object file, relative to the install location of TrustBase (by default, this is /usr/lib/trustbase-linux/)

The plugins section is an array of instll plugins and their corresponding information. Plugins provide additional validation measures desireable by the system administrator. Name and description fields are for administrator distinguishment of plugins. The type field refers to which API the plugin implements for its design (synchronous or asynchronous). The handler field corresponds to the type field of the addon that supports the plugin. For native C plugins, handler should be "native". The openssl boolean should be 1 if the plugin wishes to receive a STACK\_OF(X509) structure for validation and should be 0 if it wishes to not utilize openssl and receive the certificate chain in ASN.1 DER encoding. The map\_abstain\_to field and map\_error\_to fields should be set to either "valid" or "invalid" depending on what abstain and error responses from the plugin should be mapped to, respectively. The path field is the path to the plugin shared object, relative to the install location of TrustBase (by default, this is /usr/lib/trustbase-linux/)

The aggregation section specifies which enabled plugins reside in both the voting and necessary groups. Plugins in the voting group must collectively reach the percentage of valid responses specified by the congress\_threshold field for the voting group aggregate response to also be valid. All plugins within the necessary group must indicate valid responses for the group response to be valid. The conjunction of both groups is used as the final response from the policy engine.

The username field is the Unix username under which the administrator wishes to run TrustBase. If this user does not exist, it will be created when TrustBase is launched.

## State

TrustBase is currently a research prototype and may not be ready for large-scale use. As the project evolves to become more robust, we invite others to audit the code and participate in making TrustBase the best it can be. Pull requests are welcome, as well as any discussion about how to improve the system. 
