/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h> /* defines used in kernel.h */
#include <sys/module.h>
#include <sys/kernel.h> /* types used in module initialization */
#include <sys/conf.h> /* cdevsw struct */
#include <sys/bus.h> /* structs, prototypes for pci bus stuff and DEVMETHOD */
#include <sys/rman.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/proc.h>

#include <machine/bus.h>
#include <dev/pci/pcivar.h> /* For pci_get macros! */
#include <dev/pci/pcireg.h> /* The softc holds our per-instance data. */
#include <vm/vm.h>
#include <vm/uma.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

/* the PCI BDF parsing functions are kept separate so we can unit test them from userspace */
#include "pci_bdf.h"

#define MAX_BARS (PCIR_MAX_BAR_0 + 1)

#define MAX_DETACHED_DEVICES	128
static device_t detached_devices[MAX_DETACHED_DEVICES] = {};
static int num_detached = 0;

struct nic_uio_softc {
	device_t        dev_t;
	struct cdev     *my_cdev;
	int              bar_id[MAX_BARS];
	struct resource *bar_res[MAX_BARS];
	u_long           bar_start[MAX_BARS];
	u_long           bar_size[MAX_BARS];
};

/* Function prototypes */
static d_open_t         nic_uio_open;
static d_close_t        nic_uio_close;
static d_mmap_t         nic_uio_mmap;
static d_mmap_single_t  nic_uio_mmap_single;
static int              nic_uio_probe(device_t dev);
static int              nic_uio_attach(device_t dev);
static int              nic_uio_detach(device_t dev);
static int              nic_uio_shutdown(void);
static int              nic_uio_modevent(module_t mod, int type, void *arg);

static struct cdevsw uio_cdevsw = {
		.d_name        = "nic_uio",
		.d_version     = D_VERSION,
		.d_open        = nic_uio_open,
		.d_close       = nic_uio_close,
		.d_mmap        = nic_uio_mmap,
		.d_mmap_single = nic_uio_mmap_single,
};

static device_method_t nic_uio_methods[] = {
	DEVMETHOD(device_probe,    nic_uio_probe),
	DEVMETHOD(device_attach,   nic_uio_attach),
	DEVMETHOD(device_detach,   nic_uio_detach),
	DEVMETHOD_END
};

struct device {
    int vend;
    int dev;
};

DEFINE_CLASS_0(nic_uio, nic_uio_driver, nic_uio_methods, sizeof(struct nic_uio_softc));

#if __FreeBSD_version < 1400000
static devclass_t nic_uio_devclass;
DRIVER_MODULE(nic_uio, pci, nic_uio_driver, nic_uio_devclass, nic_uio_modevent, 0);
#else
DRIVER_MODULE(nic_uio, pci, nic_uio_driver, nic_uio_modevent, 0);
#endif

static int
nic_uio_mmap(struct cdev *cdev, vm_ooffset_t offset, vm_paddr_t *paddr,
		int prot, vm_memattr_t *memattr)
{
	*paddr = offset;
	return 0;
}

static int
nic_uio_mmap_single(struct cdev *cdev, vm_ooffset_t *offset, vm_size_t size,
		struct vm_object **obj, int nprot)
{
	/*
	 * The BAR index is encoded in the offset.  Divide the offset by
	 *  PAGE_SIZE to get the index of the bar requested by the user
	 *  app.
	 */
	unsigned bar = *offset/PAGE_SIZE;
	struct nic_uio_softc *sc = cdev->si_drv1;

	if (bar >= MAX_BARS)
		return EINVAL;

	if (sc->bar_res[bar] == NULL) {
		sc->bar_id[bar] = PCIR_BAR(bar);

		if (PCI_BAR_IO(pci_read_config(sc->dev_t, sc->bar_id[bar], 4)))
			sc->bar_res[bar] = bus_alloc_resource_any(sc->dev_t, SYS_RES_IOPORT,
					&sc->bar_id[bar], RF_ACTIVE);
		else
			sc->bar_res[bar] = bus_alloc_resource_any(sc->dev_t, SYS_RES_MEMORY,
					&sc->bar_id[bar], RF_ACTIVE);
	}
	if (sc->bar_res[bar] == NULL)
		return ENXIO;

	sc->bar_start[bar] = rman_get_start(sc->bar_res[bar]);
	sc->bar_size[bar] = rman_get_size(sc->bar_res[bar]);

	device_printf(sc->dev_t, "Bar %u @ %lx, size %lx\n", bar,
			sc->bar_start[bar], sc->bar_size[bar]);

	*offset = sc->bar_start[bar];
	*obj = vm_pager_allocate(OBJT_DEVICE, cdev, size, nprot, *offset,
				curthread->td_ucred);
	return 0;
}


int
nic_uio_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{
	return 0;
}

int
nic_uio_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{
	return 0;
}

static int
nic_uio_probe (device_t dev)
{
	int i;
	unsigned int domain = pci_get_domain(dev);
	unsigned int bus = pci_get_bus(dev);
	unsigned int device = pci_get_slot(dev);
	unsigned int function = pci_get_function(dev);

	char bdf_str[256];
	char *token, *remaining;

	/* First check if we found this on load */
	for (i = 0; i < num_detached; i++)
		if (domain == pci_get_domain(detached_devices[i]) &&
		    bus == pci_get_bus(detached_devices[i]) &&
		    device == pci_get_slot(detached_devices[i]) &&
		    function == pci_get_function(detached_devices[i])) {
			device_set_desc(dev, "DPDK PCI Device");
			return BUS_PROBE_SPECIFIC;
		}

	/* otherwise check if it's a new device and if it matches the BDF */
	memset(bdf_str, 0, sizeof(bdf_str));
	TUNABLE_STR_FETCH("hw.nic_uio.bdfs", bdf_str, sizeof(bdf_str));
	remaining = bdf_str;
	while (remaining != NULL && remaining[0] != '\0') {
		struct pci_bdf bdf;
		int status;

		status = pci_bdf_parse_next(&remaining, &token, &bdf);
		if (status == 0)
			break;
		if (status < 0)
			continue;

		if (bdf.domain == domain && bdf.bus == bus &&
				bdf.devid == device && bdf.function == function) {

			if (num_detached < MAX_DETACHED_DEVICES) {
				printf("%s: probed dev=%p\n",
					       __func__, dev);
				detached_devices[num_detached++] = dev;
				device_set_desc(dev, "DPDK PCI Device");
				return BUS_PROBE_SPECIFIC;
			} else {
				printf("%s: reached MAX_DETACHED_DEVICES=%d. dev=%p won't be reattached\n",
						__func__, MAX_DETACHED_DEVICES,
						dev);
				break;
			}
		}
	}

	return ENXIO;
}

static int
nic_uio_attach(device_t dev)
{
	int i;
	struct nic_uio_softc *sc;

	sc = device_get_softc(dev);
	sc->dev_t = dev;
	sc->my_cdev = make_dev(&uio_cdevsw, device_get_unit(dev),
			UID_ROOT, GID_WHEEL, 0600, "uio@pci:%u:%u:%u",
			pci_get_bus(dev), pci_get_slot(dev), pci_get_function(dev));
	if (sc->my_cdev == NULL)
		return ENXIO;
	sc->my_cdev->si_drv1 = sc;

	for (i = 0; i < MAX_BARS; i++)
		sc->bar_res[i] = NULL;

	pci_enable_busmaster(dev);

	return 0;
}

static int
nic_uio_detach(device_t dev)
{
	int i;
	struct nic_uio_softc *sc;
	sc = device_get_softc(dev);

	for (i = 0; i < MAX_BARS; i++)
		if (sc->bar_res[i] != NULL) {

			if (PCI_BAR_IO(pci_read_config(dev, sc->bar_id[i], 4)))
				bus_release_resource(dev, SYS_RES_IOPORT, sc->bar_id[i],
						sc->bar_res[i]);
			else
				bus_release_resource(dev, SYS_RES_MEMORY, sc->bar_id[i],
						sc->bar_res[i]);
		}

	if (sc->my_cdev != NULL)
		destroy_dev(sc->my_cdev);
	return 0;
}

static void
nic_uio_load(void)
{
	struct pci_bdf bdfs[MAX_DETACHED_DEVICES];
	unsigned int count = 0;
	device_t dev;
	char bdf_str[256];
	char *token, *remaining;
	int status;

	memset(bdf_str, 0, sizeof(bdf_str));
	TUNABLE_STR_FETCH("hw.nic_uio.bdfs", bdf_str, sizeof(bdf_str));
	remaining = bdf_str;
	printf("nic_uio: hw.nic_uio.bdfs = '%s'\n", bdf_str);
	while (remaining != NULL && remaining[0] != '\0') {
		if (count == nitems(bdfs)) {
			printf("nic_uio: too many PCI addresses in hw.nic_uio.bdfs, ignoring the rest\n");
			break;
		}
		status = pci_bdf_parse_next(&remaining, &token, &bdfs[count]);
		if (status == 0)
			break;
		if (status < 0) {
			printf("nic_uio: ignoring invalid PCI address '%s' in hw.nic_uio.bdfs\n",
			       token);
			continue;
		}
		count++;
	}

	for (unsigned int i = 0; i < count; i++) {
		const struct pci_bdf *bdf = &bdfs[i];

		dev = pci_find_dbsf(bdf->domain, bdf->bus, bdf->devid, bdf->function);
		if (dev == NULL)
			continue;

		if (num_detached < MAX_DETACHED_DEVICES) {
			printf("nic_uio_load: detaching and storing dev=%p\n",
			       dev);
			detached_devices[num_detached++] = dev;
		} else {
			printf("nic_uio_load: reached MAX_DETACHED_DEVICES=%d. dev=%p won't be reattached\n",
			       MAX_DETACHED_DEVICES, dev);
		}
		device_detach(dev);
	}
}

static void
nic_uio_unload(void)
{
	int i;
	printf("nic_uio_unload: entered...\n");

	for (i = 0; i < num_detached; i++) {
		printf("nic_uio_unload: calling to device_probe_and_attach for dev=%p...\n",
			detached_devices[i]);
		device_probe_and_attach(detached_devices[i]);
		printf("nic_uio_unload: done.\n");
	}

	printf("nic_uio_unload: leaving...\n");
}

static int
nic_uio_shutdown(void)
{
	return 0;
}

static int
nic_uio_modevent(module_t mod, int type, void *arg)
{

	switch (type) {
	case MOD_LOAD:
		nic_uio_load();
		break;
	case MOD_UNLOAD:
		nic_uio_unload();
		break;
	case MOD_SHUTDOWN:
		nic_uio_shutdown();
		break;
	default:
		break;
	}

	return 0;
}
