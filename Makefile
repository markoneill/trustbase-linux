trustbase_linux-objs := loader.o \
		       interceptor/interceptor.o \
		       interceptor/connection_state.o \
		       handshake-handler/handshake_handler.o \
		       handshake-handler/communications.o \
		       util/utils.o \
		       util/ktb_logging.o

#test_interceptor-objs := interceptor/test/test_loader.o \
#		         interceptor/interceptor.o \
#		         interceptor/connection_state.o \
#			 interceptor/test/test_handler.o \
#			 util/utils.o

#obj-m += test_interceptor.o
obj-m += trustbase_linux.o

CC = gcc
CCFLAGS = -Wall -O3 -fpic -g
LIBS = -lnl-3 -lnl-genl-3 -lcrypto -lssl -lconfig -ldl -lpython2.7 -lpthread -lsqlite3 -lcap
INCLUDES = -I/usr/include/libnl3 -I/usr/include/python2.7

POLICY_ENGINE_SRC = policy-engine/plugins.c \
		    policy-engine/addons.c \
		    policy-engine/configuration.c \
		    policy-engine/netlink.c \
		    policy-engine/query.c \
		    policy-engine/query_queue.c \
		    policy-engine/linked_list.c \
		    policy-engine/openssl_hostname_validation.c \
		    policy-engine/ca_validation.c \
		    policy-engine/tb_logging.c \
		    policy-engine/notifications.c \
		    policy-engine/sni_parser.c \
		    policy-engine/tb_user.c \
		    policy-engine/policy_engine.c

POLICY_ENGINE_OBJ = $(POLICY_ENGINE_SRC:%.c=%.o)
POLICY_ENGINE_EXE = policy_engine

NATIVE_LIB_SRC = native/native.c \
		 native/netlink.c
NATIVE_LIB_OBJ = $(NATIVE_LIB_SRC:%.c=%.o)
NATIVE_LIB_EXE = native_test

PYTHON_PLUGINS_ADDON_SRC = policy-engine/addons/python_plugins.c
PYTHON_PLUGINS_ADDON_OBJ = $(PYTHON_PLUGINS_ADDON_SRC:%.c=%.o)
PYTHON_PLUGINS_ADDON_SO = policy-engine/addons/python_plugins.so

RAW_TEST_PLUGIN_SRC = policy-engine/plugins/raw_test.c
RAW_TEST_PLUGIN_OBJ = $(RAW_TEST_PLUGIN_SRC:%.c=%.o)
RAW_TEST_PLUGIN_SO = policy-engine/plugins/raw_test.so

OPENSSL_TEST_PLUGIN_SRC = policy-engine/plugins/openssl_test.c
OPENSSL_TEST_PLUGIN_OBJ = $(OPENSSL_TEST_PLUGIN_SRC:%.c=%.o)
OPENSSL_TEST_PLUGIN_SO = policy-engine/plugins/openssl_test.so

ASYNC_TEST_PLUGIN_SRC = policy-engine/plugins/async_test.c
ASYNC_TEST_PLUGIN_OBJ = $(ASYNC_TEST_PLUGIN_SRC:%.c=%.o)
ASYNC_TEST_PLUGIN_SO = policy-engine/plugins/async_test.so

WHITELIST_PLUGIN_SRC = policy-engine/plugins/whitelist_plugin/whitelist.c
WHITELIST_PLUGIN_OBJ = $(WHITELIST_PLUGIN_SRC:%.c=%.o)
WHITELIST_PLUGIN_SO = policy-engine/plugins/whitelist_plugin/whitelist.so

CERT_PIN_PLUGIN_SRC = policy-engine/plugins/cert_pinning/certificate_pinning.c
CERT_PIN_PLUGIN_OBJ = $(CERT_PIN_PLUGIN_SRC:%.c=%.o)
CERT_PIN_PLUGIN_SO = policy-engine/plugins/cert_pinning/certificate_pinning.so

CIPHER_SUITE_PLUGIN_SRC = policy-engine/plugins/cipher_suite.c
CIPHER_SUITE_PLUGIN_OBJ = $(CIPHER_SUITE_PLUGIN_SRC:%.c=%.o)
CIPHER_SUITE_PLUGIN_SO = policy-engine/plugins/cipher_suite.so

WHITELIST_PINNING_HYBRID_PLUGIN_SRC = policy-engine/plugins/whitelist_pinning_hybrid/whitelist_pinning_hybrid.c
WHITELIST_PINNING_HYBRID_PLUGIN_OBJ = $(WHITELIST_PINNING_HYBRID_PLUGIN_SRC:%.c=%.o)
WHITELIST_PINNING_HYBRID_PLUGIN_SO = policy-engine/plugins/whitelist_pinning_hybrid/whitelist_pinning_hybrid.so

CRLSET_H = policy-engine/plugins/crlset.h
CRLSET_SO = policy-engine/plugins/crlset.so

SIMPLE_SERVER_SRC = userspace_tests/simple_server.c
SIMPLE_SERVER_OBJ = $(SIMPLE_SERVER_SRC:%.c=%.o)
SIMPLE_SERVER_EXE = simple_server

SIMPLE_CLIENT_SRC = userspace_tests/simple_client.c
SIMPLE_CLIENT_OBJ = $(SIMPLE_CLIENT_SRC:%.c=%.o)
SIMPLE_CLIENT_EXE = simple_client

CERT_TEST_SRC = userspace_tests/cert_sandbox.c
CERT_TEST_OBJ = $(CERT_TEST_SRC:%.c=%.o)
CERT_TEST_EXE = cert_test

ALL_PYTHON_PLUGIN_SRC = $(wildcard policy-engine/plugins/*.py)

all: addons trustbase

addons: $(POLICY_ENGINE_EXE) $(NATIVE_LIB_EXE) $(PYTHON_PLUGINS_ADDON_SO) $(ASYNC_TEST_PLUGIN_SO) $(OPENSSL_TEST_PLUGIN_SO) $(RAW_TEST_PLUGIN_SO) $(SIMPLE_SERVER_EXE) $(SIMPLE_CLIENT_EXE) $(CERT_TEST_EXE) $(WHITELIST_PLUGIN_SO) $(CERT_PIN_PLUGIN_SO) $(CIPHER_SUITE_PLUGIN_SO) $(WHITELIST_PINNING_HYBRID_PLUGIN_SO)

trustbase:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

$(POLICY_ENGINE_EXE) : $(POLICY_ENGINE_OBJ)
	$(CC) $(CCFLAGS) $^ -o $@ $(LIBS)

$(NATIVE_LIB_EXE) : $(NATIVE_LIB_OBJ)
	$(CC) $(CCFLAGS) $^ -o $@ $(LIBS)

$(PYTHON_PLUGINS_ADDON_SO) : $(PYTHON_PLUGINS_ADDON_OBJ)
	$(CC) -shared $^ -o $@ -I/usr/include/python2.7 -lpython2.7

$(RAW_TEST_PLUGIN_SO) : $(RAW_TEST_PLUGIN_OBJ)
	$(CC) -shared $^ -o $@

$(ASYNC_TEST_PLUGIN_SO) : $(ASYNC_TEST_PLUGIN_OBJ)
	$(CC) -shared $^ -o $@

$(OPENSSL_TEST_PLUGIN_SO) : $(OPENSSL_TEST_PLUGIN_OBJ)
	$(CC) -shared $^ -o $@

$(WHITELIST_PLUGIN_SO) : $(WHITELIST_PLUGIN_OBJ)
	$(CC) -shared $^ -o $@

$(CERT_PIN_PLUGIN_SO) : $(CERT_PIN_PLUGIN_OBJ)
	$(CC) -shared -lsqlite3 $^ -o $@

$(CIPHER_SUITE_PLUGIN_SO) : $(CIPHER_SUITE_PLUGIN_OBJ)
	$(CC) -shared $(LIBS) $^ -o $@

$(WHITELIST_PINNING_HYBRID_PLUGIN_SO) : $(WHITELIST_PINNING_HYBRID_PLUGIN_OBJ)
	$(CC) -shared $^ -o $@

$(SIMPLE_SERVER_EXE) : $(SIMPLE_SERVER_OBJ)
	$(CC) $(CCFLAGS) $^ -o $@ $(LIBS)

$(SIMPLE_CLIENT_EXE) : $(SIMPLE_CLIENT_OBJ)
	$(CC) $(CCFLAGS) $^ -o $@ $(LIBS)

$(CERT_TEST_EXE) : $(CERT_TEST_OBJ)
	$(CC) $(CCFLAGS) $^ -o $@ $(LIBS)

%.o : %.c
	$(CC) $(CCFLAGS) -c $< $(INCLUDES) -o $@

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf *.o *.so $(PYTHON_PLUGINS_ADDON_SO) $(ASYNC_TEST_PLUGIN_SO) $(OPENSSL_TEST_PLUGIN_SO) $(RAW_TEST_PLUGIN_SO) $(CRLSET_SO) $(POLICY_ENGINE_EXE) $(SIMPLE_SERVER_EXE) $(SIMPLE_CLIENT_EXE) $(CERT_TEST_EXE) $(NATIVE_LIB_EXE)  

PREFIX = /usr/lib/trustbase-linux


INSTALL_FILES = $(POLICY_ENGINE_EXE) $(PYTHON_PLUGINS_ADDON_SO) $(ASYNC_TEST_PLUGIN_SO) $(OPENSSL_TEST_PLUGIN_SO) $(RAW_TEST_PLUGIN_SO) $(WHITELIST_PLUGIN_SO) $(CERT_PIN_PLUGIN_SO) $(CIPHER_SUITE_PLUGIN_SO) $(POLICY_ENGINE_EXE) $(ALL_PYTHON_PLUGIN_SRC)

.PHONY: install-addons
install-addons: addons
	mkdir -p $(PREFIX)
	mkdir -p $(PREFIX)/sslsplit
	for FILE in $(INSTALL_FILES); do \
		mkdir -p "`dirname "$(PREFIX)/$$FILE"`"; \
		cp $$FILE $(PREFIX)/$$FILE; \
	done
	cp -r policy-engine/plugin-config $(PREFIX)/policy-engine/
	cp -r certs $(PREFIX)/
	cp sslsplit/sslsplit $(PREFIX)/sslsplit/
	cp policy-engine/trustbase.cfg $(PREFIX)/policy-engine/trustbase.cfg

.PHONY: link-config
link-config: install-addons
	ln -sf $(PREFIX)/policy-engine/trustbase.cfg /etc/trustbase.cfg

.PHONY: install-trustbase
install-trustbase: trustbase
	mkdir -p $(PREFIX)
	cp trustbase_linux.ko $(PREFIX)/
	cp Module.symvers $(PREFIX)/
	cp modules.order $(PREFIX)/

.PHONY: install
install: all install-addons link-config install-trustbase
