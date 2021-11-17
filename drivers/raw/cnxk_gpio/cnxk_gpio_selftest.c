/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <rte_cycles.h>
#include <rte_rawdev.h>
#include <rte_rawdev_pmd.h>
#include <rte_service.h>

#include "cnxk_gpio.h"
#include "rte_pmd_cnxk_gpio.h"

#define CNXK_GPIO_BUFSZ 128

static int
cnxk_gpio_attr_exists(const char *attr)
{
	struct stat st;

	return !stat(attr, &st);
}

static int
cnxk_gpio_read_attr(char *attr, char *val)
{
	FILE *fp;
	int ret;

	fp = fopen(attr, "r");
	if (!fp)
		return -errno;

	ret = fscanf(fp, "%s", val);
	if (ret < 0)
		return -errno;
	if (ret != 1)
		return -EIO;

	ret = fclose(fp);
	if (ret)
		return -errno;

	return 0;
}

#define CNXK_GPIO_ERR_STR(err, str, ...) do {                                  \
	if (err) {                                                             \
		RTE_LOG(ERR, PMD, "%s:%d: " str " (%d)\n", __func__, __LINE__, \
			##__VA_ARGS__, err);                                   \
		goto out;                                                      \
	}                                                                      \
} while (0)

static int
cnxk_gpio_validate_attr(char *attr, const char *expected)
{
	char buf[CNXK_GPIO_BUFSZ];
	int ret;

	ret = cnxk_gpio_read_attr(attr, buf);
	if (ret)
		return ret;

	if (strncmp(buf, expected, sizeof(buf)))
		return -EIO;

	return 0;
}

#define CNXK_GPIO_PATH_FMT "/sys/class/gpio/gpio%d"

static int
cnxk_gpio_test_input(uint16_t dev_id, int base, int gpio)
{
	char buf[CNXK_GPIO_BUFSZ];
	int ret, n;

	n = snprintf(buf, sizeof(buf), CNXK_GPIO_PATH_FMT, base + gpio);
	snprintf(buf + n, sizeof(buf) - n, "/direction");

	ret = rte_pmd_gpio_set_pin_dir(dev_id, gpio, CNXK_GPIO_PIN_DIR_IN);
	CNXK_GPIO_ERR_STR(ret, "failed to set dir to input");
	ret = cnxk_gpio_validate_attr(buf, "in");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

	ret = rte_pmd_gpio_set_pin_value(dev_id, gpio, 1) |
	      rte_pmd_gpio_set_pin_value(dev_id, gpio, 0);
	if (!ret) {
		ret = -EIO;
		CNXK_GPIO_ERR_STR(ret, "input pin overwritten");
	}

	snprintf(buf + n, sizeof(buf) - n, "/edge");

	ret = rte_pmd_gpio_set_pin_edge(dev_id, gpio,
					CNXK_GPIO_PIN_EDGE_FALLING);
	CNXK_GPIO_ERR_STR(ret, "failed to set edge to falling");
	ret = cnxk_gpio_validate_attr(buf, "falling");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

	ret = rte_pmd_gpio_set_pin_edge(dev_id, gpio,
					CNXK_GPIO_PIN_EDGE_RISING);
	CNXK_GPIO_ERR_STR(ret, "failed to change edge to rising");
	ret = cnxk_gpio_validate_attr(buf, "rising");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

	ret = rte_pmd_gpio_set_pin_edge(dev_id, gpio, CNXK_GPIO_PIN_EDGE_BOTH);
	CNXK_GPIO_ERR_STR(ret, "failed to change edge to both");
	ret = cnxk_gpio_validate_attr(buf, "both");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

	ret = rte_pmd_gpio_set_pin_edge(dev_id, gpio, CNXK_GPIO_PIN_EDGE_NONE);
	CNXK_GPIO_ERR_STR(ret, "failed to set edge to none");
	ret = cnxk_gpio_validate_attr(buf, "none");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

	/*
	 * calling this makes sure kernel driver switches off inverted
	 * logic
	 */
	rte_pmd_gpio_set_pin_dir(dev_id, gpio, CNXK_GPIO_PIN_DIR_IN);

out:
	return ret;
}

static int
cnxk_gpio_open_mem(void)
{
	int ret = 0, fd;

	fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd < 0)
		ret = -errno;

	return ret;
}

static void
cnxk_gpio_close_mem(int fd)
{
	if (fd >= 0)
		close(fd);
}

#define GPIO_INTRX(a) (803000000800ull + (a) * 0x8)

static int
cnxk_gpio_map_gpio_intrx(int fd, int gpio, void **va)
{
	uint64_t mask;
	long size;

	size = sysconf(_SC_PAGESIZE);
	mask = (uint64_t)size - 1;
	*va = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		   GPIO_INTRX(gpio) & ~mask);
	if (*va == MAP_FAILED)
		return -errno;

	*(char *)va += GPIO_INTRX(gpio) & mask;

	return 0;
}

static void
cnxk_gpio_unmap_gpio_intrx(int gpio, void *va)
{
	uint64_t mask;
	long size;

	if (!va)
		return;

	size = sysconf(_SC_PAGESIZE);
	mask = (uint64_t)size - 1;
	munmap((char *)va - (GPIO_INTRX(gpio) & mask), size);
}

static int
cnxk_gpio_trigger_irq(int gpio)
{
	void *va;
	int ret, fd;

	fd = cnxk_gpio_open_mem();
	if (fd < 0)
		return fd;

	ret = cnxk_gpio_map_gpio_intrx(fd, gpio, &va);
	if (ret) {
		cnxk_gpio_close_mem(fd);
		return ret;
	}

	/* set INTR_W1S bit */
	*(volatile uint64_t *)va = 2;
	cnxk_gpio_unmap_gpio_intrx(gpio, va);
	cnxk_gpio_close_mem(fd);

	return 0;
}

static void
cnxk_gpio_irq_handler(int gpio, void *data)
{
	*(int *)data = gpio;
}

static int
cnxk_gpio_test_irq(uint16_t dev_id, int gpio)
{
	int irq_data, ret;

	ret = rte_pmd_gpio_set_pin_dir(dev_id, gpio, CNXK_GPIO_PIN_DIR_IN);
	CNXK_GPIO_ERR_STR(ret, "failed to set dir to input");

	irq_data = 0;
	ret = rte_pmd_gpio_register_irq(dev_id, gpio, rte_lcore_id(),
					cnxk_gpio_irq_handler, &irq_data);
	CNXK_GPIO_ERR_STR(ret, "failed to register irq handler");

	ret = rte_pmd_gpio_enable_interrupt(dev_id, gpio,
					    CNXK_GPIO_PIN_EDGE_RISING);
	CNXK_GPIO_ERR_STR(ret, "failed to enable interrupt");

	ret = cnxk_gpio_trigger_irq(gpio);
	CNXK_GPIO_ERR_STR(ret, "failed to trigger irq");
	rte_delay_ms(1);
	ret = *(volatile int *)&irq_data == gpio ? 0 : -EIO;
	CNXK_GPIO_ERR_STR(ret, "failed to test irq");

	ret = rte_pmd_gpio_disable_interrupt(dev_id, gpio);
	CNXK_GPIO_ERR_STR(ret, "failed to disable interrupt");

	ret = rte_pmd_gpio_unregister_irq(dev_id, gpio);
	CNXK_GPIO_ERR_STR(ret, "failed to unregister irq handler");
out:
	rte_pmd_gpio_disable_interrupt(dev_id, gpio);
	rte_pmd_gpio_unregister_irq(dev_id, gpio);

	return ret;
}

static int
cnxk_gpio_test_output(uint16_t dev_id, int base, int gpio)
{
	char buf[CNXK_GPIO_BUFSZ];
	int ret, val, n;

	n = snprintf(buf, sizeof(buf), CNXK_GPIO_PATH_FMT, base + gpio);

	snprintf(buf + n, sizeof(buf) - n, "/direction");
	ret = rte_pmd_gpio_set_pin_dir(dev_id, gpio, CNXK_GPIO_PIN_DIR_OUT);
	CNXK_GPIO_ERR_STR(ret, "failed to set dir to out");
	ret = cnxk_gpio_validate_attr(buf, "out");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

	snprintf(buf + n, sizeof(buf) - n, "/value");
	ret = rte_pmd_gpio_set_pin_value(dev_id, gpio, 0);
	CNXK_GPIO_ERR_STR(ret, "failed to set value to 0");
	ret = cnxk_gpio_validate_attr(buf, "0");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);
	ret = rte_pmd_gpio_get_pin_value(dev_id, gpio, &val);
	CNXK_GPIO_ERR_STR(ret, "failed to read value");
	if (val)
		ret = -EIO;
	CNXK_GPIO_ERR_STR(ret, "read %d instead of 0", val);

	ret = rte_pmd_gpio_set_pin_value(dev_id, gpio, 1);
	CNXK_GPIO_ERR_STR(ret, "failed to set value to 1");
	ret = cnxk_gpio_validate_attr(buf, "1");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);
	ret = rte_pmd_gpio_get_pin_value(dev_id, gpio, &val);
	CNXK_GPIO_ERR_STR(ret, "failed to read value");
	if (val != 1)
		ret = -EIO;
	CNXK_GPIO_ERR_STR(ret, "read %d instead of 1", val);

	snprintf(buf + n, sizeof(buf) - n, "/direction");
	ret = rte_pmd_gpio_set_pin_dir(dev_id, gpio, CNXK_GPIO_PIN_DIR_LOW);
	CNXK_GPIO_ERR_STR(ret, "failed to set dir to low");
	ret = cnxk_gpio_validate_attr(buf, "out");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);
	snprintf(buf + n, sizeof(buf) - n, "/value");
	ret = cnxk_gpio_validate_attr(buf, "0");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

	snprintf(buf + n, sizeof(buf) - n, "/direction");
	ret = rte_pmd_gpio_set_pin_dir(dev_id, gpio, CNXK_GPIO_PIN_DIR_HIGH);
	CNXK_GPIO_ERR_STR(ret, "failed to set dir to high");
	ret = cnxk_gpio_validate_attr(buf, "out");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);
	snprintf(buf + n, sizeof(buf) - n, "/value");
	ret = cnxk_gpio_validate_attr(buf, "1");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

	snprintf(buf + n, sizeof(buf) - n, "/edge");
	ret = rte_pmd_gpio_set_pin_edge(dev_id, gpio,
					CNXK_GPIO_PIN_EDGE_FALLING);
	ret = ret == 0 ? -EIO : 0;
	CNXK_GPIO_ERR_STR(ret, "changed edge to falling");
	ret = cnxk_gpio_validate_attr(buf, "none");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

	ret = rte_pmd_gpio_set_pin_edge(dev_id, gpio,
					CNXK_GPIO_PIN_EDGE_RISING);
	ret = ret == 0 ? -EIO : 0;
	CNXK_GPIO_ERR_STR(ret, "changed edge to rising");
	ret = cnxk_gpio_validate_attr(buf, "none");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

	ret = rte_pmd_gpio_set_pin_edge(dev_id, gpio, CNXK_GPIO_PIN_EDGE_BOTH);
	ret = ret == 0 ? -EIO : 0;
	CNXK_GPIO_ERR_STR(ret, "changed edge to both");
	ret = cnxk_gpio_validate_attr(buf, "none");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

	/* this one should succeed */
	ret = rte_pmd_gpio_set_pin_edge(dev_id, gpio, CNXK_GPIO_PIN_EDGE_NONE);
	CNXK_GPIO_ERR_STR(ret, "failed to change edge to none");
	ret = cnxk_gpio_validate_attr(buf, "none");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

	snprintf(buf + n, sizeof(buf) - n, "/active_low");
	ret = rte_pmd_gpio_set_pin_active_low(dev_id, gpio, 1);
	CNXK_GPIO_ERR_STR(ret, "failed to set active_low to 1");
	ret = cnxk_gpio_validate_attr(buf, "1");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

	ret = rte_pmd_gpio_get_pin_active_low(dev_id, gpio, &val);
	CNXK_GPIO_ERR_STR(ret, "failed to read active_low");
	if (val != 1)
		ret = -EIO;
	CNXK_GPIO_ERR_STR(ret, "read %d instead of 1", val);

	snprintf(buf + n, sizeof(buf) - n, "/value");
	ret = rte_pmd_gpio_set_pin_value(dev_id, gpio, 1);
	CNXK_GPIO_ERR_STR(ret, "failed to set value to 1");
	ret = cnxk_gpio_validate_attr(buf, "1");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

	ret = rte_pmd_gpio_set_pin_value(dev_id, gpio, 0);
	CNXK_GPIO_ERR_STR(ret, "failed to set value to 0");
	ret = cnxk_gpio_validate_attr(buf, "0");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

	snprintf(buf + n, sizeof(buf) - n, "/active_low");
	ret = rte_pmd_gpio_set_pin_active_low(dev_id, gpio, 0);
	CNXK_GPIO_ERR_STR(ret, "failed to set active_low to 0");
	ret = cnxk_gpio_validate_attr(buf, "0");
	CNXK_GPIO_ERR_STR(ret, "failed to validate %s", buf);

out:
	return ret;
}

int
cnxk_gpio_selftest(uint16_t dev_id)
{
	struct cnxk_gpiochip *gpiochip;
	unsigned int queues, i, size;
	char buf[CNXK_GPIO_BUFSZ];
	struct rte_rawdev *rawdev;
	struct cnxk_gpio *gpio;
	int ret;

	rawdev = rte_rawdev_pmd_get_named_dev("cnxk_gpio");
	gpiochip = rawdev->dev_private;

	queues = rte_rawdev_queue_count(dev_id);
	if (queues == 0)
		return -ENODEV;

	ret = rte_rawdev_start(dev_id);
	if (ret)
		return ret;

	for (i = 0; i < queues; i++) {
		RTE_LOG(INFO, PMD, "testing queue %d (gpio%d)\n", i,
			gpiochip->base + i);

		ret = rte_rawdev_queue_conf_get(dev_id, i, &size, sizeof(size));
		if (ret) {
			RTE_LOG(ERR, PMD,
				"failed to read queue configuration (%d)\n",
				ret);
			continue;
		}

		if (size != 1) {
			RTE_LOG(ERR, PMD, "wrong queue size received\n");
			continue;
		}

		ret = rte_rawdev_queue_setup(dev_id, i, NULL, 0);
		if (ret) {
			RTE_LOG(ERR, PMD, "failed to setup queue (%d)\n", ret);
			continue;
		}

		gpio = gpiochip->gpios[i];
		snprintf(buf, sizeof(buf), CNXK_GPIO_PATH_FMT, gpio->num);
		if (!cnxk_gpio_attr_exists(buf)) {
			RTE_LOG(ERR, PMD, "%s does not exist\n", buf);
			continue;
		}

		ret = cnxk_gpio_test_input(dev_id, gpiochip->base, i);
		if (ret)
			goto release;

		ret = cnxk_gpio_test_irq(dev_id, i);
		if (ret)
			goto release;

		ret = cnxk_gpio_test_output(dev_id, gpiochip->base, i);
		if (ret)
			goto release;

release:
		ret = rte_rawdev_queue_release(dev_id, i);
		if (ret) {
			RTE_LOG(ERR, PMD, "failed to release queue (%d)\n",
				ret);
			continue;
		}

		if (cnxk_gpio_attr_exists(buf)) {
			RTE_LOG(ERR, PMD, "%s still exists\n", buf);
			continue;
		}
	}

	return 0;
}
