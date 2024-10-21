#include <errno.h>
#include <rte_pci_tph.h>

int
rte_init_tph_acpi__dsm_args(uint16_t lcore_id, uint8_t type,
			    uint8_t cache_level, uint8_t ph,
			    struct rte_tph_acpi__dsm_args *args)
{
	RTE_SET_USED(lcore_id);
	RTE_SET_USED(type);
	RTE_SET_USED(cache_level);
	RTE_SET_USED(ph);

	if (!args)
		return -EINVAL;
	/* Use libhwloc or other mechanism provided by DPDK to
	 * map lcore_id and cache_level to hardware IDs for
	 * initializing args.
	 */
	return -ENOTSUP;
}
