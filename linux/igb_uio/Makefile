DPDK_HEADERS ?= /usr/local/include
RTE_KERNELDIR ?= /lib/modules/`uname -r`/build

all:
	make EXTRA_CFLAGS="-I $(DPDK_HEADERS)" -C $(RTE_KERNELDIR)/ M=$(PWD)

clean:
	make -C $(RTE_KERNELDIR)/ M=$(PWD) clean
