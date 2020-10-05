obj-m += igb_uio.o
DPDK_INSTALL=/usr/local/include

all:
		make EXTRA_CFLAGS="-I $(DPDK_INSTALL)" -C /lib/modules/`uname -r`/build/ M=$(PWD)

clean:
	    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
