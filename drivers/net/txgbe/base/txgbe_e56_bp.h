#ifndef _TXGBE_E56_BP_H_
#define _TXGBE_E56_BP_H_

#define TXGBE_10G_FEC_REQ       BIT(15)
#define TXGBE_10G_FEC_ABL       BIT(14)
#define TXGBE_25G_BASE_FEC_REQ  BIT(13)
#define TXGBE_25G_RS_FEC_REQ    BIT(12)

int txgbe_e56_set_link_to_kr(struct txgbe_hw *hw);
void txgbe_e65_bp_down_event(struct txgbe_hw *hw);
int handle_e56_bkp_an73_flow(struct txgbe_hw *hw);

#endif
