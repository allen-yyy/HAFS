/* SPDX-License-Identifier: MIT */

#define SEG_BLOCK 1024

#pragma pack(1)

struct super_sector
{
    char identifier[4];
    unsigned long long size;
    unsigned short block_size;
    unsigned short block_map_start;
    unsigned int inode_map_start;
    unsigned int zero_seg_start;
    unsigned int root_inode;
    unsigned int type;
#define FS_TYPE_HD      0x1
#define FS_TYPE_CD      0x2
#define FS_TYPE_FLOPPY  0x4
#define FS_TYPE_USB     0x8
#define FS_TYPE_BOOT    0x10
#define FS_TYPE_HIDE    0x20
#define FS_TYPE_RDONLY  0x40
    unsigned int inode_per_seg;
    unsigned int seg_number;
    unsigned int block_map_size;
    unsigned int inode_map_size;
    unsigned int crc;
};

struct seg_super_sector
{
    char identifier[4];
    unsigned short block_number;
    unsigned short block_map_rel_start;
    unsigned short inode_map_rel_start;
    unsigned short inode_rel_start;
    unsigned int block_left;
    unsigned int inode_left;
    unsigned int crc;
};

struct inode
{
    unsigned int type;
#define INODE_PRESENT       0x1
#define INODE_FILE          0x2
#define INODE_DIR           0x4
#define INODE_HIDE          0x8
#define INODE_RDONLY        0x10
#define INODE_SYSTEM        0x20
#define INODE_LONG_NAME     0x40
#define INODE_ADDITIONAL    0x80
    unsigned long long file_size;
    unsigned int additional_block;
    unsigned int direct[12];
    unsigned int indirect_1[8];
    unsigned int indirect_2[4];
    unsigned int indirect_3[4];
};

#define ADDITION_INODE      0x1
#define ADDITION_LONG_NAME  0x2
#define ADDITION_LINK_INODE 0x4
#define ADDITION_FA_INODE   0x8

struct MBR
{
    char jump[3];
    char oem[8];
    unsigned short sector_size;
    unsigned char block_sector;
    unsigned short reserve_sector;
    unsigned int unused1;
    unsigned short type;
    unsigned int unused1;
    unsigned int sig;
    unsigned long long sector_number;
    unsigned int version;
};

#ifndef NULL
#define NULL (void *) 0
#endif

#define _f(x) (x?1:0)
#define round(x,y) ((x)/(y)+_f(((x)%(y))))