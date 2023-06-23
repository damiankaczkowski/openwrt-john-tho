/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 John Thomson
 */

#ifndef _ROUTERBOOT_LZ77_H_
#define _ROUTERBOOT_LZ77_H_

#include <linux/errno.h>

#define LZ77_MK_MAX_ENCODED 0x1000
#define LZ77_MK_MAX_DECODED 0x40000

/* examples have all decompressed to start with DRE\x00 */
#define LZ77_MK_EXPECTED_OUT 0x44524500

/* the look behind window
 * unknown, for long instruction match offsets up to
 * 6449 have been seen (would need 21 counter bits: 4 to 12 + 11 to 0)
 * conservative value here: 27 provides offset up to 0x8000 bytes
 */
#define LZ77_MK_MAX_COUNT_BIT_LEN 27

#ifdef CONFIG_MIKROTIK_RB_SYSFS_WLAN_LZ77
int lz77_mikrotik_wlan_decompress(
		const unsigned char *in,
		size_t in_len,
		unsigned char *out,
		size_t *out_len);
#else
static inline int lz77_mikrotik_wlan_decompress(
		const unsigned char *in,
		size_t in_len,
		unsigned char *out,
		size_t *out_len)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_MIKROTIK_RB_SYSFS_WLAN_LZ77 */
#endif /* _ROUTERBOOT_LZ77_H_ */