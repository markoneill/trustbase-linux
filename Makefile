obj-m += trusthub_linux.o
trusthub_linux-objs := loader.o connection_state.o utils.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
