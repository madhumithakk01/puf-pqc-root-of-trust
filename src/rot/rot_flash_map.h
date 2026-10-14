#ifndef ROT_FLASH_MAP_H
#define ROT_FLASH_MAP_H

/*
 * Flash layout of the 4 MB device. Must match firmware/pt/pt.json;
 * tools/ci/check_flash_map.py enforces it.
 *
 * All offsets are from the start of flash (XIP address 0x10000000).
 */

#define ROT_FLASH_SECTOR      0x1000u
#define ROT_FLASH_PAGE        0x100u
#define ROT_FLASH_TOTAL       0x400000u

#define ROT_REGION_ROT_OFF    0x000000u
#define ROT_REGION_ROT_SIZE   0x040000u

#define ROT_REGION_APP_A_OFF  0x040000u
#define ROT_REGION_APP_A_SIZE 0x130000u
#define ROT_REGION_APP_B_OFF  0x170000u
#define ROT_REGION_APP_B_SIZE 0x130000u

#define ROT_REGION_STAGING_OFF  0x2A0000u
#define ROT_REGION_STAGING_SIZE 0x130000u

#define ROT_REGION_DATA_OFF   0x3D0000u
#define ROT_REGION_DATA_SIZE  0x030000u

/* rot_data sectors: offset = ROT_REGION_DATA_OFF + n * ROT_FLASH_SECTOR */
#define ROT_SECTOR_HLP1       0u
#define ROT_SECTOR_ANC1       1u
#define ROT_SECTOR_RBC1_A     2u
#define ROT_SECTOR_RBC1_B     3u
#define ROT_SECTOR_JNL1_A     4u
#define ROT_SECTOR_JNL1_B     5u
#define ROT_SECTOR_MBX1       6u
#define ROT_SECTOR_ATR2       7u
#define ROT_SECTOR_RCP1_FIRST 8u
#define ROT_RCP1_RING         8u
#define ROT_SECTOR_SPARE_FIRST 16u
#define ROT_DATA_SECTORS      48u

#define ROT_DATA_SECTOR_OFF(n) (ROT_REGION_DATA_OFF + (n) * ROT_FLASH_SECTOR)

/* Slots (A = 0, B = 1) */
#define ROT_SLOT_OFF(s) ((s) ? ROT_REGION_APP_B_OFF : ROT_REGION_APP_A_OFF)

/* The application binary starts this far into a slot (SBI1 header + APM1). */
#define ROT_APP_BIN_OFFSET    0x1000u

#endif
