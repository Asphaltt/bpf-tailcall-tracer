CONFIG_STACK_VALIDATION=

ccflags-y  :=  -I/usr/src/linux-headers-$(shell uname -r)/include/ -I../ebpf/headers

obj-m += bpf-tailcall-trace.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
