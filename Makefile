obj-m += trusthub_linux.o
trusthub_linux-objs := loader.o interceptor.o connection_state.o secure_handshake_parser.o communications.o utils.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -o policy_engine policy_engine.c -I/usr/include/libnl3 -lnl-3 -lnl-genl-3 -lcrypto

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm policy_engine
