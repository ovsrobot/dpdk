#ifndef __RNP_API_H__
#define __RNP_API_H__
int
rnp_init_hw(struct rte_eth_dev *dev);
int
rnp_reset_hw(struct rte_eth_dev *dev, struct rnp_hw *hw);
#endif /* __RNP_API_H__ */
