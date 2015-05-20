trusthub_linux-objs := loader.o \
		       interceptor/interceptor.o \
		       interceptor/connection_state.o \
		       handshake-handler/handshake_handler.o \
		       handshake-handler/communications.o \
		       util/utils.o

test_interceptor-objs := interceptor/test/test_loader.o \
		         interceptor/interceptor.o \
		         interceptor/connection_state.o \
			 interceptor/test/test_handler.o \
			 util/utils.o

obj-m += test_interceptor.o
obj-m += trusthub_linux.o

CC = gcc
CCFLAGS = -Wall -O3 -fpic
LIBS = -lnl-3 -lnl-genl-3 -lcrypto -lssl -lconfig -ldl
INCLUDES = -I/usr/include/libnl3

POLICY_ENGINE_SRC = policy-engine/plugins.c policy-engine/configuration.c policy-engine/policy_engine.c
POLICY_ENGINE_OBJ = $(POLICY_ENGINE_SRC:%.c=%.o)
POLICY_ENGINE_EXE = policy_engine

RAW_TEST_PLUGIN_SRC = policy-engine/plugins/raw_test.c
RAW_TEST_PLUGIN_OBJ = $(RAW_TEST_PLUGIN_SRC:%.c=%.o)
RAW_TEST_PLUGIN_SO = policy-engine/plugins/raw_test.so

OPENSSL_TEST_PLUGIN_SRC = policy-engine/plugins/openssl_test.c
OPENSSL_TEST_PLUGIN_OBJ = $(OPENSSL_TEST_PLUGIN_SRC:%.c=%.o)
OPENSSL_TEST_PLUGIN_SO = policy-engine/plugins/openssl_test.so

SIMPLE_SERVER_SRC = userspace_tests/simple_server.c
SIMPLE_SERVER_OBJ = $(SIMPLE_SERVER_SRC:%.c=%.o)
SIMPLE_SERVER_EXE = simple_server

SIMPLE_CLIENT_SRC = userspace_tests/simple_client.c
SIMPLE_CLIENT_OBJ = $(SIMPLE_CLIENT_SRC:%.c=%.o)
SIMPLE_CLIENT_EXE = simple_client

CERT_TEST_SRC = userspace_tests/cert_sandbox.c
CERT_TEST_OBJ = $(CERT_TEST_SRC:%.c=%.o)
CERT_TEST_EXE = cert_test

all: $(POLICY_ENGINE_EXE) $(OPENSSL_TEST_PLUGIN_SO) $(RAW_TEST_PLUGIN_SO) $(SIMPLE_SERVER_EXE) $(SIMPLE_CLIENT_EXE) $(CERT_TEST_EXE)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

$(POLICY_ENGINE_EXE) : $(POLICY_ENGINE_OBJ)
	$(CC) $(CCFLAGS) $^ -o $@ $(LIBS)

$(RAW_TEST_PLUGIN_SO) : $(RAW_TEST_PLUGIN_OBJ)
	$(CC) -shared $^ -o $@

$(OPENSSL_TEST_PLUGIN_SO) : $(OPENSSL_TEST_PLUGIN_OBJ)
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
	rm -rf *.o *.so $(OPENSSL_TEST_PLUGIN_SO) $(RAW_TEST_PLUGIN_SO) $(POLICY_ENGINE_EXE) $(SIMPLE_SERVER_EXE) $(SIMPLE_CLIENT_EXE) $(CERT_TEST_EXE)
