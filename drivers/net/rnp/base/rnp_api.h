#ifndef __RNP_API_H__
#define __RNP_API_H__
int
rnp_init_hw(struct rte_eth_dev *dev);
int
rnp_reset_hw(struct rte_eth_dev *dev, struct rnp_hw *hw);
int
rnp_get_mac_addr(struct rte_eth_dev *dev, uint8_t *macaddr);
int
rnp_set_default_mac(struct rte_eth_dev *dev, uint8_t *mac_addr);
int
rnp_set_rafb(struct rte_eth_dev *dev, uint8_t *addr,
		uint8_t vm_pool, uint8_t index);
int
rnp_clear_rafb(struct rte_eth_dev *dev,
		uint8_t vm_pool, uint8_t index);
#endif /* __RNP_API_H__ */
