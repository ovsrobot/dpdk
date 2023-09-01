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
