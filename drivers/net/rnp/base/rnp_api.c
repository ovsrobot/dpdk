#include "rnp.h"
#include "rnp_api.h"

int
rnp_init_hw(struct rte_eth_dev *dev)
{
	const struct rnp_mac_api *ops = RNP_DEV_TO_MAC_OPS(dev);
	struct rnp_hw *hw = RNP_DEV_TO_HW(dev);

	if (ops->init_hw)
		return ops->init_hw(hw);
	return -EOPNOTSUPP;
}

int
rnp_reset_hw(struct rte_eth_dev *dev, struct rnp_hw *hw)
{
	const struct rnp_mac_api *ops = RNP_DEV_TO_MAC_OPS(dev);

	if (ops->reset_hw)
		return ops->reset_hw(hw);
	return -EOPNOTSUPP;
}

int
rnp_get_mac_addr(struct rte_eth_dev *dev, uint8_t *macaddr)
{
	struct rnp_eth_port *port = RNP_DEV_TO_PORT(dev);
	const struct rnp_mac_api *ops = RNP_DEV_TO_MAC_OPS(dev);

	if (!macaddr)
		return -EINVAL;
	if (ops->get_mac_addr)
		return ops->get_mac_addr(port, port->attr.nr_lane, macaddr);
	return -EOPNOTSUPP;
}

int
rnp_set_default_mac(struct rte_eth_dev *dev, uint8_t *mac_addr)
{
	const struct rnp_mac_api *ops = RNP_DEV_TO_MAC_OPS(dev);
	struct rnp_eth_port *port = RNP_DEV_TO_PORT(dev);

	if (ops->set_default_mac)
		return ops->set_default_mac(port, mac_addr);
	return -EOPNOTSUPP;
}

int
rnp_set_rafb(struct rte_eth_dev *dev, uint8_t *addr,
	     uint8_t vm_pool, uint8_t index)
{
	const struct rnp_mac_api *ops = RNP_DEV_TO_MAC_OPS(dev);
	struct rnp_eth_port *port = RNP_DEV_TO_PORT(dev);

	if (ops->set_rafb)
		return ops->set_rafb(port, addr, vm_pool, index);
	return -EOPNOTSUPP;
}

int
rnp_clear_rafb(struct rte_eth_dev *dev,
	       uint8_t vm_pool, uint8_t index)
{
	const struct rnp_mac_api *ops = RNP_DEV_TO_MAC_OPS(dev);
	struct rnp_eth_port *port = RNP_DEV_TO_PORT(dev);

	if (ops->clear_rafb)
		return ops->clear_rafb(port, vm_pool, index);
	return -EOPNOTSUPP;
}
