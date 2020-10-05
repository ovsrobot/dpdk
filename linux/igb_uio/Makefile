DPDK_HEADERS ?= /usr/local/include
RTE_KERNELDIR ?= `uname -r`

all:
		make EXTRA_CFLAGS="-I $(DPDK_HEADERS)" -C /lib/modules/$(RTE_KERNELDIR)/build/ M=$(PWD)

clean:
	    make -C /lib/modules/$(RTE_KERNELDIR)/build M=$(PWD) clean
