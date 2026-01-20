/* SPDX-License-Identifier: MIT */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
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

#define ADDITION_LONG_NAME      0x2
#define ADDITION_FA_INODE       0x8
#define ADDITION_CREATE_TIME    0x10
#define ADDITION_ACCESS_TIME    0x20
#define ADDITION_MODIFY_TIME    0x40

struct MBR
{
    char jump[3];
    char oem[8];
    unsigned short sector_size;
    unsigned char block_sector;
    unsigned short reserve_sector;
    unsigned int unused1;
    unsigned short type;
    unsigned int unused2;
    unsigned int sig;
    unsigned long long sector_number;
    unsigned int version;
    unsigned int super_sector_start;
};

struct dir_entry
{
    unsigned int next_record;
    unsigned int inode;
    char *name;
};

#ifndef NULL
#define NULL (void *) 0
#endif

#define _f(x) (x?1:0)
#define round(x,y) ((x)/(y)+_f(((x)%(y))))

#define RESERVE_SECTOR 0

int hafs_make_fs(int storage, unsigned long long size, unsigned int block_size, unsigned int inode_number);
int hafs_load_fs(int storage);
unsigned int hafs_create_file(int slot, const char *path, unsigned int pathlen, const char *filename, unsigned int namelen);
int hafs_delete_file(int slot, const char *filename, int namelen);
char *hafs_read_file(int slot, const char *file_name, unsigned int namelen, unsigned long long pos, unsigned long long size);
int hafs_write_file(int slot, const char *file_name, unsigned int namelen, unsigned long long pos, unsigned long long size, const char *buf);
unsigned int hafs_make_dir(int slot, const char *path, unsigned int pathlen, const char *dirname, unsigned int namelen);
int hafs_rewrite_file(int slot, const char *file_name, unsigned int namelen, unsigned long long size, const char *buf);
unsigned long long hafs_get_file_size(int slot, const char *filename, unsigned int namelen);
struct dir_entry *hafs_dir_list(int slot, const char *dirname, unsigned int namelen, unsigned int *entry_number);
unsigned int hafs_get_file_attribute(int slot, const char *filename, unsigned int namelen);
unsigned long long hafs_get_file_size_by_inode(int slot, unsigned int inode);
unsigned int hafs_get_file_attribute_by_inode(int slot, unsigned int inode);
int hafs_file_exist(int slot, const char *filename, unsigned int namelen);
int hafs_file_access(int slot, unsigned int inode, unsigned int o_time);
int hafs_file_modify(int slot, unsigned int inode, unsigned int o_time);
int hafs_file_read_access_time(int slot, unsigned int inode);
int hafs_file_read_modify_time(int slot, unsigned int inode);
int hafs_file_write_additional_block(int slot, unsigned int inode, char *buffer, unsigned int size);
int hafs_file_read_create_time(int slot, unsigned int inode);