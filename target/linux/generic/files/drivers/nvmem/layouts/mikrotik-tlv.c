// SPDX-License-Identifier: GPL-2.0-only
/*
 * Mikrotik tlv config NVMEM cells provider
 *
 * Based on the nvmem onie TLV driver written by: Miquel Raynal <miquel.raynal@bootlin.com>
 * Alongside the OpenWrt rbcfg (Gabor Juhos <juhosg@openwrt.org>) and
 * OpenWrt Mikrotik rb_sysfs (Thibaut VARÈNE <hacks+kernel@slashdirt.org>)
 * drivers
 */

#include <linux/etherdevice.h>
#include <linux/nvmem-consumer.h>
#include <linux/nvmem-provider.h>
#include <linux/of.h>

#define MIKROTIK_TLV_MAX_LEN		0x2000
#define MIKROTIK_TLV_HDR_SOFT_CRC_SZ	4

enum mikrotik_tlv_type {
	MIKROTIK_TLV_ERROR = 0,
	MIKROTIK_TLV_HARD = (('H') | ('a' << 8) | ('r' << 16) | ('d' << 24)),
	MIKROTIK_TLV_SOFT = (('S') | ('o' << 8) | ('f' << 16) | ('t' << 24)),
	MIKROTIK_TLV_ERD = (('D') | ('R' << 8) | ('E' << 16)),
};

enum mikrotik_tlv_hard {
	//RB_HARD_ID_UNKNOWN		= 0x01,
	RB_HARD_ID_FLASH_INFO		= 0x03,
	RB_HARD_ID_MAC_ADDRESS_PACK	= 0x04,
	RB_HARD_ID_BOARD_PRODUCT_CODE	= 0x05,
	RB_HARD_ID_BIOS_VERSION		= 0x06,
	RB_HARD_ID_SDRAM_TIMINGS	= 0x08,
	RB_HARD_ID_DEVICE_TIMINGS	= 0x09,
	RB_HARD_ID_SOFTWARE_ID		= 0x0a,
	RB_HARD_ID_SERIAL_NUMBER	= 0x0b,
	RB_HARD_ID_MEMORY_SIZE		= 0x0d,
	RB_HARD_ID_MAC_ADDRESS_COUNT	= 0x0e,
	//RB_HARD_ID_UNKNOWN		= 0x12,
	//RB_HARD_ID_UNKNOWN		= 0x13,
	//RB_HARD_ID_UNKNOWN		= 0x14,
	RB_HARD_ID_HW_OPTIONS		= 0x15,
	RB_HARD_ID_WLAN_DATA		= 0x16,
	RB_HARD_ID_BOARD_IDENTIFIER	= 0x17,
	//RB_HARD_ID_UNKNOWN		= 0x19,
	//RB_HARD_ID_UNKNOWN		= 0x1a,
	//RB_HARD_ID_UNKNOWN		= 0x1b,
	//RB_HARD_ID_UNKNOWN		= 0x1c,
	RB_HARD_ID_PRODUCT_NAME		= 0x21,
	//RB_HARD_ID_UNKNOWN		= 0x23,
	//RB_HARD_ID_UNKNOWN		= 0x25,
	RB_HARD_ID_DEFCONF		= 0x26,
	RB_HARD_ID_BOARD_REVISION	= 0x27,
	RB_HARD_ID_WLAN_ANTENNAS_GAINS	= 0x28,
	RB_HARD_ID_MAX,
};

enum mikrotik_tlv_hard_hwopts {
	RB_HARD_OPT_NO_UART		= BIT(0),
	RB_HARD_OPT_HAS_VOLTAGE		= BIT(1),
	RB_HARD_OPT_HAS_USB		= BIT(2),
	RB_HARD_OPT_HAS_ATTINY		= BIT(3),
	RB_HARD_OPT_PULSE_DUTY_CYCLE	= BIT(9),
	RB_HARD_OPT_NO_NAND		= BIT(14),
	RB_HARD_OPT_HAS_LCD		= BIT(15),
	RB_HARD_OPT_HAS_POE_OUT		= BIT(16),
	RB_HARD_OPT_HAS_uSD		= BIT(17),
	RB_HARD_OPT_HAS_SIM		= BIT(18),
	//RB_HARD_OPT_UNKNOWN		= BIT(19),
	RB_HARD_OPT_HAS_SFP		= BIT(20),
	RB_HARD_OPT_HAS_WIFI		= BIT(21),
	RB_HARD_OPT_HAS_TS_FOR_ADC	= BIT(22),
	//RB_HARD_OPT_UNKNOWN		= BIT(27),
	RB_HARD_OPT_HAS_PLC		= BIT(29),
	RB_HARD_OPT_MAX			= BIT(31),
};

enum mikrotik_tlv_soft {
	RB_SOFT_ID_UART_SPEED		= 0x01,
	RB_SOFT_ID_BOOT_DELAY		= 0x02,
	RB_SOFT_ID_BOOT_DEVICE		= 0x03,
	RB_SOFT_ID_BOOT_KEY		= 0x04,
	RB_SOFT_ID_CPU_MODE		= 0x05,
	RB_SOFT_ID_BIOS_VERSION		= 0x06,
	//RB_SOFT_ID_UNKNOWN		= 0x07,
	RB_SOFT_ID_BOOT_PROTOCOL	= 0x09,
	//RB_SOFT_ID_UNKNOWN		= 0x0a,
	//RB_SOFT_ID_UNKNOWN		= 0x0b,
	RB_SOFT_ID_CPU_FREQ_IDX		= 0x0c,
	RB_SOFT_ID_BOOTER		= 0x0d,
	RB_SOFT_ID_SILENT_BOOT		= 0x0f,
	//RB_SOFT_ID_UNKNOWN		= 0x11,
	//RB_SOFT_ID_UNKNOWN		= 0x15,
	//RB_SOFT_ID_UNKNOWN		= 0x17,
	//RB_SOFT_ID_UNKNOWN		= 0x1b,
	RB_SOFT_ID_PROTECTED		= 0x1f,
	//RB_SOFT_ID_UNKNOWN		= 0x21,
	RB_SOFT_ID_MAX			= 0x22,
};

enum mikrotik_tlv_erd {
	RB_ERD_ID_SOLO		= 0x0001,
	RB_ERD_ID_MULTI_8001	= 0x8001,
	RB_ERD_ID_MULTI_8201	= 0x8201,
};

struct mikrotik_tlv_hdr {
	u8 id[4];
} __packed;

struct mikrotik_tlv {
	u16 type;
	u16 len;
} __packed;

static const char *mikrotik_tlv_hard_cell_name(u8 type)
{
	switch (type) {
	case RB_HARD_ID_MAC_ADDRESS_PACK:
		return "mac-address";
	case RB_HARD_ID_BOARD_PRODUCT_CODE:
		return "part-number";
	case RB_HARD_ID_BIOS_VERSION:
		return "backup-booter-version";
	case RB_HARD_ID_SERIAL_NUMBER:
		return "serial-number";
	case 0x0d:
		return "memory-size";
	case 0x0e:
		return "num-macs";
	case 0x15:
		return "hw-options";
	case 0x16:
		return "wlan-data";
	case 0x17:
		return "part-devcode";
	case 0x21:
		return "product-name";
	case 0x28:
		return "wlan-antenna-gain";
	default:
		break;
	}

	return NULL;
}

static const char *mikrotik_tlv_soft_cell_name(u8 type)
{
	switch (type) {
	case 0x01:
		return "uart-speed";
	case 0x02:
		return "boot-delay";
	case 0x03:
		return "boot-device";
	case 0x04:
		return "boot-interrupt-key-del";
	case 0x05:
		return "cpu-mode-regular";
	case 0x06:
		return "booter-version";
	case 0x09:
		return "netboot-use-dhcp";
	case 0x0c:
		return "cpu-speed";
	case 0x0d:
		return "bootloader-use-backup";
	case 0x0f:
		return "silent-boot";
	default:
		break;
	}

	return NULL;
}

static const char *mikrotik_tlv_cell_name(u8 type, enum mikrotik_tlv_type config_type)
{
	if (config_type == MIKROTIK_TLV_HARD)
		return mikrotik_tlv_hard_cell_name(type);
	else if (config_type == MIKROTIK_TLV_SOFT)
		return mikrotik_tlv_soft_cell_name(type);
	return NULL;
}

static int mikrotik_tlv_mac_read_cb(void *priv, const char *id, int index,
		unsigned int offset, void *buf,
		size_t bytes)
{
	if (index)
		eth_addr_add(buf, index);

	pr_info("Mikrotik TLV NVMEM cell read ethaddr: %pM + %d\n",
			buf, index);

	return 0;
}

static int mikrotik_tlv_crc_is_valid(struct device *dev,
		struct nvmem_device *nvmem, size_t nvmem_len)
{
	u32 *config_data;
	u8 *crc_ptr;
	u32 *read_crc;
	u32 calc_crc, stored_crc;
	int ret;

	nvmem_len = nvmem_device_size(nvmem);

	config_data = kmalloc(nvmem_len, GFP_KERNEL);
	if (!config_data)
		return -ENOMEM;
	ret = nvmem_device_read(nvmem, 0, nvmem_len, config_data);
	if (ret != nvmem_len)
		dev_warn(dev, "Read for CRC was short\n");

	crc_ptr = (u8 *)config_data + sizeof(struct mikrotik_tlv_hdr);
	read_crc = (u32 *)crc_ptr;
	stored_crc = *read_crc;
	dev_dbg(dev, "mem ptr: 0x%px, CRC ptr: %px\n", config_data, read_crc);
	dev_dbg(dev, "CRC val: %x\n", *read_crc);
	dev_dbg(dev, "CRC copy val: %x\n", stored_crc);
	*read_crc = 0;
	dev_dbg(dev, "CRC val after zero: %x\n", *read_crc);
	calc_crc = ~crc32(~0, config_data, nvmem_len);
	if (stored_crc != calc_crc) {
		dev_warn(dev, "Invalid CRC read: 0x%08x, expected: 0x%08x\n",
			stored_crc, calc_crc);
		ret = -EIO;
		ret = 0;
	} else
		ret = 0;

	kfree(config_data);
	return ret;
}


static nvmem_cell_post_process_t mikrotik_tlv_read_cb(u8 type, u8 *buf, enum mikrotik_tlv_type config_type)
{
	if (config_type == MIKROTIK_TLV_HARD) {
		switch (type) {
		case 0x04:
			return &mikrotik_tlv_mac_read_cb;
		default:
			break;
		}
	}

	return NULL;
}

static int mikrotik_tlv_add_cells(struct device *dev,
		struct nvmem_device *nvmem, size_t data_len, u8 *data,
		size_t data_start_offset,
		enum mikrotik_tlv_type config_type)
{
	struct nvmem_cell_info cell = {};
	struct device_node *layout;
	struct mikrotik_tlv tlv;
	unsigned int offset = data_start_offset;
	int ret;
	bool parse_finished = false;

	dev_dbg(dev, "Mikrotik TLV add_cells start\n");

	layout = of_nvmem_layout_get_container(nvmem);
	if (!layout)
		return -ENOENT;

	/* would like to use nvmem->size, but private struct
	 * alternative is to read MTD block size chunks
	 */
	while (true) {
		ret = nvmem_device_read(nvmem, offset, sizeof(tlv), &tlv);
		if (ret != sizeof(tlv)) {
			dev_err(dev, "error reading nvmem device: %d\n", ret);
			break;
		}

		if (offset > MIKROTIK_TLV_MAX_LEN) {
			dev_err(dev, "TLV total length too long\n");
			break;
		}

		if (data_len && (offset + tlv.len >= data_len)) {
			dev_err(dev, "Out of bounds field (0x%x bytes at 0x%x)\n",
				tlv.len, offset);
			break;
		}

		if (tlv.type == 0) {
			dev_dbg(dev, "TLV ID null, parse complete\n");
			parse_finished = true;
			offset += sizeof(tlv) + tlv.len;
			break;
		}

		if (tlv.len == 0) {
			dev_err(dev, "TLV len null, parse err\n");
			break;
		}

		cell.name = mikrotik_tlv_cell_name(tlv.type, config_type);
		if (!cell.name) {
			dev_warn(dev, "TLV ID unknown: 0x%x\n", tlv.type);
			offset += sizeof(tlv) + tlv.len;
			continue;
		}

		cell.offset = offset + sizeof(tlv);
		if (config_type == MIKROTIK_TLV_HARD) {
			switch (tlv.type) {
			case 0x04:
				cell.bytes = ETH_ALEN;
				cell.raw_len = tlv.len;
				break;
			default:
				cell.bytes = tlv.len;
				cell.raw_len = tlv.len;
			}
		} else {
			cell.bytes = tlv.len;
			cell.raw_len = tlv.len;
		}

		cell.np = of_get_child_by_name(layout, cell.name);
		if (cell.np)
			dev_dbg(dev, "nvmem cell: %s using OF node: %s\n",
					cell.name,
					cell.np->name);
		cell.read_post_process = mikrotik_tlv_read_cb(tlv.type, data + offset + sizeof(tlv), config_type);

		ret = nvmem_add_one_cell(nvmem, &cell);
		if (ret) {
			dev_err(dev, "error adding nvmem cell: %d\n", ret);
			of_node_put(layout);
			return ret;
		}
		dev_dbg(dev, "add nvmem cell name %s, offset: 0x%x, len %d: %d\n",
				cell.name,
				cell.offset,
				cell.raw_len,
				ret);

		offset += sizeof(tlv) + tlv.len;
	}

	if (parse_finished && config_type == MIKROTIK_TLV_SOFT) {
		if (!mikrotik_tlv_crc_is_valid(dev, nvmem, offset)) {
			ret = -EINVAL;
		}
	}

	of_node_put(layout);

	return 0;
}

/*
static bool mikrotik_tlv_hdr_is_hard(struct device *dev, struct mikrotik_tlv_hdr *hdr)
{
	if (!memcmp(hdr->id, (unsigned int)MIKROTIK_TLV_HARD, sizeof(hdr->id))) {
		dev_dbg(dev, "Mikrotik hard_config header\n");
		return true;
	}
	return false;
}

static bool mikrotik_tlv_hdr_is_soft(struct device *dev, struct mikrotik_tlv_hdr *hdr)
{
	if (!memcmp(hdr->id, (unsigned int)MIKROTIK_TLV_SOFT, sizeof(hdr->id))) {
		dev_dbg(dev, "Mikrotik soft_config header\n");
		return true;
	}
	return false;
}

static bool mikrotik_tlv_hdr_is_erd(struct device *dev, struct mikrotik_tlv_hdr *hdr)
{
	if (!memcmp(hdr->id, (unsigned int)MIKROTIK_TLV_ERD, sizeof(hdr->id))) {
		dev_dbg(dev, "Mikrotik ERD header\n");
		return true;
	}
	return false;
}

static enum mikrotik_tlv_type mikrotik_tlv_hdr_is_valid(struct device *dev, struct mikrotik_tlv_hdr *hdr)
{
	if (mikrotik_tlv_hdr_is_hard(dev, hdr))
		return MIKROTIK_TLV_HARD;
	else if (mikrotik_tlv_hdr_is_soft(dev, hdr))
		return MIKROTIK_TLV_SOFT;
	else if (mikrotik_tlv_hdr_is_erd(dev, hdr))
		return MIKROTIK_TLV_ERD;
	else {
		dev_err(dev, "Mikrotik config header invalid: 0x%04x\n",
				*(u32 *)&hdr->id);
		return MIKROTIK_TLV_ERROR;
	}
	*/
static enum mikrotik_tlv_type mikrotik_tlv_hdr_is_valid(struct device *dev, struct mikrotik_tlv_hdr *hdr)
{
	u32 *config_type = (u32 *)&hdr->id;
	switch (*config_type) {
	case MIKROTIK_TLV_HARD:
		dev_dbg(dev, "Mikrotik hard_config header\n");
		return MIKROTIK_TLV_HARD;
	case MIKROTIK_TLV_SOFT:
		dev_dbg(dev, "Mikrotik soft_config header\n");
		return MIKROTIK_TLV_SOFT;
	case MIKROTIK_TLV_ERD:
		dev_dbg(dev, "Mikrotik ERD header\n");
		return MIKROTIK_TLV_ERD;
	default:
		break;
	}
	dev_err(dev, "Mikrotik config header invalid: 0x%04x\n",
			*(u32 *)&hdr->id);
	return MIKROTIK_TLV_ERROR;
}

static int mikrotik_tlv_parse_table(struct device *dev, struct nvmem_device *nvmem,
				struct nvmem_layout *layout)
{
	struct mikrotik_tlv_hdr hdr;
	size_t hdr_len;
	//u8 *table;
	int ret;
	enum mikrotik_tlv_type config_type;
	const size_t device_size = nvmem_device_size(nvmem);
	u8 *config_data;

	dev_dbg(dev, "Mikrotik NVMEM TLV parser loading\n");

	ret = nvmem_device_read(nvmem, 0, sizeof(hdr), &hdr);
	if (ret < 0) {
		dev_err(dev, "Mikrotik config TLV initial read failed: %d\n",
				ret);
		return ret;
	}

	hdr_len = sizeof(hdr.id);
	config_type = mikrotik_tlv_hdr_is_valid(dev, &hdr);
	if (config_type == MIKROTIK_TLV_ERROR) {
		dev_err(dev, "Invalid Mikrotik config TLV header\n");
		return -EINVAL;
	} else if (config_type == MIKROTIK_TLV_SOFT)
		hdr_len += MIKROTIK_TLV_HDR_SOFT_CRC_SZ;

	config_data = kmalloc(device_size, GFP_KERNEL);
	if (!config_data)
		return -ENOMEM;

	ret = nvmem_device_read(nvmem, 0, device_size, config_data);
	if (ret != device_size) {
		dev_err(dev, "Mikrotik config TLV error reading config data: %d\n",
				ret);
		return ret;
	}

	ret = mikrotik_tlv_add_cells(dev, nvmem, 0,
			NULL, hdr_len, config_type);
	if (ret) {
		dev_err(dev, "add_cells error: %d\n", ret);
	}

	kfree(config_data);

	return ret;
}

static const struct of_device_id mikrotik_tlv_of_match_table[] = {
	{ .compatible = "mikrotik,tlv-layout", },
	{},
};
MODULE_DEVICE_TABLE(of, mikrotik_tlv_of_match_table);

static struct nvmem_layout mikrotik_tlv_layout = {
	.name = "Mikrotik tlv configs layout",
	.of_match_table = mikrotik_tlv_of_match_table,
	.add_cells = mikrotik_tlv_parse_table,
};
module_nvmem_layout_driver(mikrotik_tlv_layout);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("John Thomson <git@johnthomson.fastmail.com.au>");
MODULE_DESCRIPTION("NVMEM layout driver for Mikrotik config TLV table parsing");
