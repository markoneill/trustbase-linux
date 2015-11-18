trusthub_linux-objs := loader.o \
		       interceptor/interceptor.o \
		       interceptor/connection_state.o \
		       handshake-handler/handshake_handler.o \
		       handshake-handler/communications.o \
		       util/utils.o \

test_interceptor-objs := interceptor/test/test_loader.o \
		         interceptor/interceptor.o \
		         interceptor/connection_state.o \
			 interceptor/test/test_handler.o \
			 util/utils.o

obj-m += test_interceptor.o
obj-m += trusthub_linux.o

CC = gcc
CCFLAGS = -Wall -O3 -fpic -g
LIBS = -lnl-3 -lnl-genl-3 -lcrypto -lssl -lconfig -ldl -lpython2.7 -lpthread
INCLUDES = -I/usr/include/libnl3 -I/usr/include/python2.7

POLICY_ENGINE_SRC = policy-engine/plugins.c \
		    policy-engine/addons.c \
		    policy-engine/configuration.c \
		    policy-engine/netlink.c \
		    policy-engine/query.c \
		    policy-engine/query_queue.c \
		    policy-engine/linked_list.c \
		    policy-engine/check_root_store.c \
		    policy-engine/debug_log.c \
		    policy-engine/policy_engine.c
POLICY_ENGINE_OBJ = $(POLICY_ENGINE_SRC:%.c=%.o)
POLICY_ENGINE_EXE = policy_engine

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

SIMPLE_SERVER_SRC = userspace_tests/simple_server.c
SIMPLE_SERVER_OBJ = $(SIMPLE_SERVER_SRC:%.c=%.o)
SIMPLE_SERVER_EXE = simple_server

SIMPLE_CLIENT_SRC = userspace_tests/simple_client.c
SIMPLE_CLIENT_OBJ = $(SIMPLE_CLIENT_SRC:%.c=%.o)
SIMPLE_CLIENT_EXE = simple_client

CERT_TEST_SRC = userspace_tests/cert_sandbox.c
CERT_TEST_OBJ = $(CERT_TEST_SRC:%.c=%.o)
CERT_TEST_EXE = cert_test

all: $(POLICY_ENGINE_EXE) $(PYTHON_PLUGINS_ADDON_SO) $(ASYNC_TEST_PLUGIN_SO) $(OPENSSL_TEST_PLUGIN_SO) $(RAW_TEST_PLUGIN_SO) $(SIMPLE_SERVER_EXE) $(SIMPLE_CLIENT_EXE) $(CERT_TEST_EXE)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

$(POLICY_ENGINE_EXE) : $(POLICY_ENGINE_OBJ)
	$(CC) $(CCFLAGS) $^ -o $@ $(LIBS)

$(PROXY_EXE) : $(PROXY_OBJ)
	$(CC) $(CCFLAGS) $^ -o $@ $(LIBS)

$(PYTHON_PLUGINS_ADDON_SO) : $(PYTHON_PLUGINS_ADDON_OBJ)
	$(CC) -shared $^ -o $@

$(RAW_TEST_PLUGIN_SO) : $(RAW_TEST_PLUGIN_OBJ)
	$(CC) -shared $^ -o $@

$(ASYNC_TEST_PLUGIN_SO) : $(ASYNC_TEST_PLUGIN_OBJ)
	$(CC) -shared $^ -o $@

$(OPENSSL_TEST_PLUGIN_SO) : $(OPENSSL_TEST_PLUGIN_OBJ)
	$(CC) -shared $^ -o $@

$(WHITELIST_PLUGIN_SO) : $(WHITELIST_PLUGIN_OBJ)
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
	rm -rf *.o *.so $(PYTHON_PLUGINS_ADDON_SO) $(ASYNC_TEST_PLUGIN_SO) $(OPENSSL_TEST_PLUGIN_SO) $(RAW_TEST_PLUGIN_SO) $(POLICY_ENGINE_EXE) $(SIMPLE_SERVER_EXE) $(SIMPLE_CLIENT_EXE) $(CERT_TEST_EXE)
