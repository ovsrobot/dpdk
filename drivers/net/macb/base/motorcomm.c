/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Phytium Technology Co., Ltd.
 */

#include "motorcomm.h"

#define YT8821_CHIP_MODE_AUTO_BX2500_SGMII	(1)
#define YT8821_CHIP_MODE_FORCE_BX2500		(0)
#define YT8821_CHIP_MODE_UTP_TO_FIBER_FORCE	(0)

struct yt8xxx_priv {
	u8 polling_mode;
	u8 chip_mode;
};

static int ytphy_read_ext(struct phy_device *phydev, uint32_t regnum)
{
	struct macb *bp = phydev->bp;
	int32_t ret, val;
	uint16_t phyad = phydev->phyad;

	ret = macb_mdio_write(bp, phyad, REG_DEBUG_ADDR_OFFSET, regnum);
	if (ret < 0)
		return ret;

	val = macb_mdio_read(bp, phyad, REG_DEBUG_DATA);

	return val;
}

static int ytphy_write_ext(struct phy_device *phydev, uint32_t regnum,
						   uint16_t val)
{
	struct macb *bp = phydev->bp;
	int32_t ret;
	uint16_t phyad = phydev->phyad;

	ret = macb_mdio_write(bp, phyad, REG_DEBUG_ADDR_OFFSET, regnum);
	if (ret < 0)
		return ret;

	ret = macb_mdio_write(bp, phyad, REG_DEBUG_DATA, val);

	return ret;
}

static int yt8512_config_init(struct phy_device *phydev)
{
	int32_t ret, val;

	/* disable auto sleep */
	val = ytphy_read_ext(phydev, YT8512_EXTREG_SLEEP_CONTROL1);
	if (val < 0)
		return val;

	val &= (~BIT(YT8512_EN_SLEEP_SW_BIT));

	ret = ytphy_write_ext(phydev, YT8512_EXTREG_SLEEP_CONTROL1, val);
	if (ret < 0)
		return ret;

	return ret;
}

static int yt8512_read_status(struct phy_device *phydev)
{
	struct macb *bp = phydev->bp;
	int32_t val;
	uint32_t speed, speed_mode, duplex;
	uint16_t phyad = phydev->phyad;

	val = macb_mdio_read(bp, phyad, REG_PHY_SPEC_STATUS);
	if (val < 0)
		return val;

	duplex = (val & YT8512_DUPLEX) >> YT8512_DUPLEX_BIT;
	speed_mode = (val & YT8512_SPEED_MODE) >> YT8512_SPEED_MODE_BIT;
	switch (speed_mode) {
	case 0:
		speed = SPEED_10;
		break;
	case 1:
		speed = SPEED_100;
		break;
	case 2:
		speed = SPEED_1000;
		break;
	default:
		speed = SPEED_UNKNOWN;
		break;
	}

	phydev->duplex = duplex;
	phydev->speed = speed;

	return 0;
}

static int yt8521_probe(struct phy_device *phydev)
{
	int32_t val;
	struct yt8xxx_priv *priv;

	priv = rte_zmalloc("motorcomm", sizeof(struct yt8xxx_priv), 0);
	if (!priv) {
		MACB_LOG(ERR, "failed to alloc yt8xxx_priv.");
		return -ENOMEM;
	}

	phydev->priv = priv;

	val = ytphy_read_ext(phydev, 0xa001);
	priv->chip_mode = val & 0x7;

	switch (priv->chip_mode) {
	case 1:
	case 4:
	case 5:
		priv->polling_mode = YT8521_PHY_MODE_FIBER;
		break;
	case 2:
	case 6:
	case 7:
		priv->polling_mode = YT8521_PHY_MODE_POLL;
		break;
	case 0:
	case 3:
	default:
		priv->polling_mode = YT8521_PHY_MODE_UTP;
	}

	return 0;
}

static int yt8521_config_init(struct phy_device *phydev)
{
	struct macb *bp = phydev->bp;
	int32_t ret, val;

	ytphy_write_ext(phydev, 0xa000, 0);

	/* disable auto sleep */
	val = ytphy_read_ext(phydev, YT8521_EXTREG_SLEEP_CONTROL1);
	if (val < 0)
		return val;
	val &= (~BIT(YT8521_EN_SLEEP_SW_BIT));
	ret = ytphy_write_ext(phydev, YT8521_EXTREG_SLEEP_CONTROL1, val);
	if (ret < 0)
		return ret;

	/* enable RXC clock when no wire plug */
	val = ytphy_read_ext(phydev, 0xc);
	if (val < 0)
		return val;
	val &= ~(1 << 12);
	ret = ytphy_write_ext(phydev, 0xc, val);
	if (ret < 0)
		return ret;

	return ret;
}

static int yt8521_soft_reset(struct phy_device *phydev)
{
	int32_t ret, val;
	struct yt8xxx_priv *priv = phydev->priv;

	if (!priv)
		return -EPERM;

	if (priv->polling_mode == YT8521_PHY_MODE_UTP) {
		ytphy_write_ext(phydev, 0xa000, 0);
		ret = genphy_soft_reset(phydev);
		if (ret < 0)
			return ret;
	}

	if (priv->polling_mode == YT8521_PHY_MODE_FIBER) {
		ytphy_write_ext(phydev, 0xa000, 2);
		ret = genphy_soft_reset(phydev);

		ytphy_write_ext(phydev, 0xa000, 0);
		if (ret < 0)
			return ret;
	}

	if (priv->polling_mode == YT8521_PHY_MODE_POLL) {
		val = ytphy_read_ext(phydev, 0xa001);
		ytphy_write_ext(phydev, 0xa001, (val & ~0x8000));

		ytphy_write_ext(phydev, 0xa000, 0);
		ret = genphy_soft_reset(phydev);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int yt8521_resume(struct phy_device *phydev)
{
	struct macb *bp = phydev->bp;
	uint32_t ctrl;
	int32_t val;
	uint16_t phyad = phydev->phyad;

	/* disable auto sleep */
	val = ytphy_read_ext(phydev, YT8521_EXTREG_SLEEP_CONTROL1);
	if (val < 0)
		return val;
	val &= (~BIT(YT8521_EN_SLEEP_SW_BIT));
	ytphy_write_ext(phydev, YT8521_EXTREG_SLEEP_CONTROL1, val);

	ytphy_write_ext(phydev, 0xa000, 0);
	ctrl = macb_mdio_read(bp, phyad, GENERIC_PHY_BMCR);
	ctrl &= ~BMCR_PDOWN;
	macb_mdio_write(bp, phyad, GENERIC_PHY_BMCR, ctrl);

	ytphy_write_ext(phydev, 0xa000, 2);
	ctrl = macb_mdio_read(bp, phyad, GENERIC_PHY_BMCR);
	ctrl &= ~BMCR_PDOWN;
	macb_mdio_write(bp, phyad, GENERIC_PHY_BMCR, ctrl);
	ytphy_write_ext(phydev, 0xa000, 0);

	rte_delay_ms(100);

	return 0;
}

static void yt8521_suspend(struct phy_device *phydev)
{
	struct macb *bp = phydev->bp;
	uint32_t ctrl;
	uint16_t phyad = phydev->phyad;

	ytphy_write_ext(phydev, 0xa000, 0);
	ctrl = macb_mdio_read(bp, phyad, GENERIC_PHY_BMCR);
	ctrl |= BMCR_PDOWN;
	macb_mdio_write(bp, phyad, GENERIC_PHY_BMCR, ctrl);

	ytphy_write_ext(phydev, 0xa000, 2);
	ctrl = macb_mdio_read(bp, phyad, GENERIC_PHY_BMCR);
	ctrl |= BMCR_PDOWN;
	macb_mdio_write(bp, phyad, GENERIC_PHY_BMCR, ctrl);
	ytphy_write_ext(phydev, 0xa000, 0);
}

static int yt8521_adjust_status(struct phy_device *phydev, int val, int is_utp)
{
	int speed_mode, duplex;
	int speed = SPEED_UNKNOWN;

	if (is_utp)
		duplex = (val & YT8512_DUPLEX) >> YT8521_DUPLEX_BIT;
	else
		duplex = 1;
	speed_mode = (val & YT8521_SPEED_MODE) >> YT8521_SPEED_MODE_BIT;
	switch (speed_mode) {
	case 0:
		if (is_utp)
			speed = SPEED_10;
		break;
	case 1:
		speed = SPEED_100;
		break;
	case 2:
		speed = SPEED_1000;
		break;
	case 3:
		break;
	default:
		speed = SPEED_UNKNOWN;
		break;
	}

	phydev->speed = speed;
	phydev->duplex = duplex;

	return 0;
}

static int yt8521_check_for_link(struct phy_device *phydev)
{
	struct macb *bp = phydev->bp;
	struct yt8xxx_priv *priv = phydev->priv;
	uint16_t phyad = phydev->phyad;
	int32_t ret;
	int32_t val;
	uint32_t link, link_utp = 0, link_fiber = 0;
	uint32_t yt8521_fiber_latch_val;
	uint32_t yt8521_fiber_curr_val;

	if (!priv)
		return -EPERM;

	if (priv->polling_mode != YT8521_PHY_MODE_FIBER) {
		/* reading UTP */
		ret = ytphy_write_ext(phydev, 0xa000, 0);
		if (ret < 0)
			return ret;

		val = macb_mdio_read(bp, phyad, REG_PHY_SPEC_STATUS);
		if (val < 0)
			return val;

		link = val & (BIT(YT8521_LINK_STATUS_BIT));
		if (link)
			link_utp = 1;
		else
			link_utp = 0;
	}

	if (priv->polling_mode != YT8521_PHY_MODE_UTP) {
		/* reading Fiber */
		ret = ytphy_write_ext(phydev, 0xa000, 2);
		if (ret < 0)
			return ret;

		val = macb_mdio_read(bp, phyad, REG_PHY_SPEC_STATUS);
		if (val < 0)
			return val;

		yt8521_fiber_latch_val = macb_mdio_read(bp, phyad, GENERIC_PHY_BMSR);
		yt8521_fiber_curr_val = macb_mdio_read(bp, phyad, GENERIC_PHY_BMSR);
		link = val & (BIT(YT8521_LINK_STATUS_BIT));
		if (link && yt8521_fiber_latch_val != yt8521_fiber_curr_val)
			link = 0;

		if (link)
			link_fiber = 1;
		else
			link_fiber = 0;
	}

	if (link_utp || link_fiber)
		phydev->link = 1;
	else
		phydev->link = 0;

	return phydev->link;
}

static int yt8521_read_status(struct phy_device *phydev)
{
	struct macb *bp = phydev->bp;
	struct yt8xxx_priv *priv = phydev->priv;
	int32_t ret;
	int32_t val;
	uint32_t link;
	uint32_t speed_mode;
	uint16_t phyad = phydev->phyad;

	if (!priv)
		return -EPERM;

	if (priv->polling_mode != YT8521_PHY_MODE_FIBER) {
		/* reading UTP */
		ret = ytphy_write_ext(phydev, 0xa000, 0);
		if (ret < 0)
			return ret;

		val = macb_mdio_read(bp, phyad, REG_PHY_SPEC_STATUS);
		if (val < 0)
			return val;

		link = val & (BIT(YT8521_LINK_STATUS_BIT));
		if (link)
			yt8521_adjust_status(phydev, val, 1);
	}

	if (priv->polling_mode != YT8521_PHY_MODE_UTP) {
		/* reading Fiber */
		ret = ytphy_write_ext(phydev, 0xa000, 2);
		if (ret < 0)
			return ret;

		val = macb_mdio_read(bp, phyad, REG_PHY_SPEC_STATUS);
		if (val < 0)
			return val;

		link = val & (BIT(YT8521_LINK_STATUS_BIT));
		if (link)
			yt8521_adjust_status(phydev, val, 0);
	}

	if (priv->polling_mode != YT8521_PHY_MODE_FIBER) {
		if (link)
			ytphy_write_ext(phydev, 0xa000, 0);
	}
	return 0;
}

static int yt8821_soft_reset(struct phy_device *phydev)
{
	int32_t ret, val;

	val = ytphy_read_ext(phydev, 0xa001);
	ytphy_write_ext(phydev, 0xa001, (val & ~0x8000));

	ytphy_write_ext(phydev, 0xa000, 0);
	ret = genphy_soft_reset(phydev);

	return ret;
}

static int yt8821_init(struct phy_device *phydev)
{
	int ret = 0;

	ret = ytphy_write_ext(phydev, 0xa000, 0x0);
	if (ret < 0)
		return ret;

	ret = ytphy_write_ext(phydev, 0x34e, 0x8008);
	if (ret < 0)
		return ret;

	ret = ytphy_write_ext(phydev, 0x4d2, 0x5200);
	if (ret < 0)
		return ret;

	ret = ytphy_write_ext(phydev, 0x4d3, 0x5200);
	if (ret < 0)
		return ret;

	ret = ytphy_write_ext(phydev, 0x372, 0x5a3c);
	if (ret < 0)
		return ret;

	ret = ytphy_write_ext(phydev, 0x336, 0xaa0a);
	if (ret < 0)
		return ret;

	ret = ytphy_write_ext(phydev, 0x340, 0x3022);
	if (ret < 0)
		return ret;

	/* soft reset */
	genphy_soft_reset(phydev);

	return ret;
}

static int yt8821_config_init(struct phy_device *phydev)
{
	int32_t ret, val;

#if (YT8821_CHIP_MODE_AUTO_BX2500_SGMII)
	ret = ytphy_write_ext(phydev, 0xa001, 0x0);
	if (ret < 0)
		return ret;
#elif (YT8821_CHIP_MODE_FORCE_BX2500)
	ret = ytphy_write_ext(phydev, 0xa001, 0x1);
	if (ret < 0)
		return ret;
#elif (YT8821_CHIP_MODE_UTP_TO_FIBER_FORCE)
	ret = ytphy_write_ext(phydev, 0xa001, 0x5);
	if (ret < 0)
		return ret;
#endif

	ret = yt8821_init(phydev);
	if (ret < 0)
		return ret;

	/* disable auto sleep */
	val = ytphy_read_ext(phydev, YT8821_EXTREG_SLEEP_CONTROL1);
	if (val < 0)
		return val;

	val &= (~BIT(YT8821_EN_SLEEP_SW_BIT));
	ret = ytphy_write_ext(phydev, YT8821_EXTREG_SLEEP_CONTROL1, val);
	if (ret < 0)
		return ret;

	return ret;
}

static int yt8821_resume(struct phy_device *phydev)
{
	uint32_t ctrl;
	struct macb *bp = phydev->bp;
	uint16_t phyad = phydev->phyad;

	ctrl = macb_mdio_read(bp, phyad, GENERIC_PHY_BMCR);
	ctrl &= ~BMCR_PDOWN;
	ctrl &= ~BMCR_ISOLATE;
	macb_mdio_write(bp, phyad, GENERIC_PHY_BMCR, ctrl);

	return 0;
}

static int yt8821_check_for_link(struct phy_device *phydev)
{
	int ret;
	int val;
	int link;
	struct macb *bp = phydev->bp;
	uint16_t phyad = phydev->phyad;

	/* reading UTP */
	ret = ytphy_write_ext(phydev, 0xa000, 0);
	if (ret < 0)
		return ret;

	val = macb_mdio_read(bp, phyad, REG_PHY_SPEC_STATUS);
	if (val < 0)
		return val;

	link = val & (BIT(YT8821_LINK_STATUS_BIT));
	if (link)
		phydev->link = 1;
	else
		phydev->link = 0;

	return phydev->link;
}

static int yt8821_adjust_status(struct phy_device *phydev, int val)
{
	int speed_mode, duplex;
	int speed_mode_bottom, speed_mode_upper;
	int speed = SPEED_UNKNOWN;

	duplex = (val & YT8821_DUPLEX) >> YT8821_DUPLEX_BIT;

	/* Bit9-Bit15-Bit14 speed mode 100---2.5G; 010---1000M; 001---100M; 000---10M */
	speed_mode_bottom = (val & YT8821_SPEED_MODE) >> YT8821_SPEED_MODE_BIT;
	speed_mode_upper = (val & BIT(YT8821_SPEED_MODE_UPPER)) >> YT8821_SPEED_MODE_UPPER;
	speed_mode = (speed_mode_upper << 2) | speed_mode_bottom;
	switch (speed_mode) {
	case 0:
		speed = SPEED_10;
		break;
	case 1:
		speed = SPEED_100;
		break;
	case 2:
		speed = SPEED_1000;
		break;
	case 4:
		speed = SPEED_2500;
		break;
	default:
		speed = SPEED_UNKNOWN;
		break;
	}

	phydev->speed = speed;
	phydev->duplex = duplex;

	return 0;
}

static int yt8821_read_status(struct phy_device *phydev)
{
	struct macb *bp = phydev->bp;
	int32_t ret;
	int32_t val;
	uint32_t link;
	uint16_t phyad = phydev->phyad;

	/* reading UTP */
	ret = ytphy_write_ext(phydev, 0xa000, 0);
	if (ret < 0)
		return ret;

	val = macb_mdio_read(bp, phyad, REG_PHY_SPEC_STATUS);
	if (val < 0)
		return val;

	link = val & (BIT(YT8521_LINK_STATUS_BIT));
	if (link) {
		yt8821_adjust_status(phydev, val);
		ytphy_write_ext(phydev, 0xa000, 0);
	}

	return 0;
}

struct phy_driver yt8512_driver = {
	.phy_id		= PHY_ID_YT8512,
	.phy_id_mask	= MOTORCOMM_PHY_ID_MASK,
	.name		= "YT8512 Ethernet",
	.soft_reset	= genphy_soft_reset,
	.config_init	= yt8512_config_init,
	.suspend	= genphy_suspend,
	.resume		= genphy_resume,
	.check_for_link		= genphy_check_for_link,
	.read_status		= yt8512_read_status,
	.force_speed_duplex	= genphy_force_speed_duplex,
};

struct phy_driver yt8521_driver = {
	.phy_id		= PHY_ID_YT8521,
	.phy_id_mask	= MOTORCOMM_PHY_ID_MASK,
	.name		= "YT8521 Ethernet",
	.soft_reset	= yt8521_soft_reset,
	.config_init	= yt8521_config_init,
	.suspend	= yt8521_suspend,
	.resume		= yt8521_resume,
	.check_for_link		= yt8521_check_for_link,
	.read_status		= yt8521_read_status,
	.force_speed_duplex	= genphy_force_speed_duplex,
	.probe		= yt8521_probe,
};

struct phy_driver yt8531S_driver = {
	.phy_id		= PHY_ID_YT8531S,
	.phy_id_mask	= MOTORCOMM_PHY_ID_MASK,
	.name		= "YT8531S Ethernet",
	.soft_reset	= yt8521_soft_reset,
	.config_init	= yt8521_config_init,
	.suspend	= yt8521_suspend,
	.resume		= yt8521_resume,
	.check_for_link		= yt8521_check_for_link,
	.read_status		= yt8521_read_status,
	.force_speed_duplex	= genphy_force_speed_duplex,
	.probe		= yt8521_probe,
};

struct phy_driver yt8531_driver = {
	.phy_id		= PHY_ID_YT8531,
	.phy_id_mask	= MOTORCOMM_PHY_ID_MASK,
	.name		= "YT8531 Ethernet",
	.soft_reset	= genphy_soft_reset,
	.suspend	= genphy_suspend,
	.resume		= genphy_resume,
	.check_for_link		= genphy_check_for_link,
	.read_status		= genphy_read_status,
	.force_speed_duplex	= genphy_force_speed_duplex,
};

struct phy_driver yt8821_driver = {
	.phy_id		= PHY_ID_YT8821,
	.phy_id_mask	= MOTORCOMM_PHY_ID_MASK,
	.name		= "YT8821 2.5Gbps Ethernet",
	.soft_reset	= yt8821_soft_reset,
	.config_init	= yt8821_config_init,
	.suspend	= genphy_suspend,
	.resume		= yt8821_resume,
	.check_for_link		= yt8821_check_for_link,
	.read_status		= yt8821_read_status,
	.force_speed_duplex	= genphy_force_speed_duplex,
};
