obj-m += trusthub_linux.o
trusthub_linux-objs := loader.o \
			interceptor/interceptor.o \
			interceptor/connection_state.o \
			handshake-handler/handshake_handler.o \
			handshake-handler/communications.o \
			util/utils.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -o policy_engine policy-engine/policy_engine.c -I/usr/include/libnl3 -lnl-3 -lnl-genl-3 -lcrypto

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm policy_engine
