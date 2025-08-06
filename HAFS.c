/* SPDX-License-Identifier: MIT */

#include "HAFS.h"

char *read_disk(int storage, unsigned long long start, unsigned int sector);
int write_disk(int storage, unsigned long long start, int sector, const void *buf);
unsigned int get_disk_type(int storage);

int bit_map_find(char *bitmap, unsigned int size)
{
    int i,k;
    for(i=0;i<round(size,8);i++)
    {
        if((bitmap[i]&0xff)!=0xff) break;
    }
    if(bitmap[i]==0xff || i==round(size,8)) return -1;
    for(k=0;k<8;k++)
    {
        if(!(bitmap[i]&(1<<k))) break;
    }
    if(i*8+k>=size) return -1;
    return i*8+k;
}

int bit_map_find_mask(char *bitmap, unsigned int size, unsigned int start)
{
    int i,k;
    if(start % 8 && (bitmap[start/8]&0xff)!=0xff)
    {
    	for(k=start & 7;k<8;k++)
	    {
	        if(!(bitmap[i]&(1<<k))) break;
	    }
	    i = start / 8;
	    if(k!=8&&i*8+k<size) return i*8+k;
	}
    for(i=round(start, 8);i<round(size,8);i++)
    {
        if((bitmap[i]&0xff)!=0xff) break;
    }
    if(bitmap[i]==0xff || i==round(size,8)) return -1;
    for(k=0;k<8;k++)
    {
        if(!(bitmap[i]&(1<<k))) break;
    }
    if(i*8+k>=size) return -1;
    return i*8+k;
}

void bit_map_set(char *bitmap, unsigned int bit)
{
    bitmap[bit>>3]|=1<<(bit&7);
    return;
}

void bit_map_unset(char *bitmap, unsigned int bit)
{
    bitmap[bit>>3]&=~(1<<(bit&7));
    return;
}

int bit_map_get(char *bitmap, unsigned int bit)
{
    return bitmap[bit>>3]&(1<<(bit&7));
}

unsigned int CRC32(unsigned char* ptr, unsigned int Size)
{
	unsigned int crcTable[256], crcTmp1;

	for (int i = 0; i<256; i++)
	{
		crcTmp1 = i;
		for (int j = 8; j>0; j--)
		{
			if (crcTmp1 & 1) crcTmp1 = (crcTmp1 >> 1) ^ 0xEDB88320L;
			else crcTmp1 >>= 1;
		}
		crcTable[i] = crcTmp1;
	}

	unsigned int crcTmp2 = 0xFFFFFFFF;
	while (Size--)
	{
		crcTmp2 = ((crcTmp2 >> 8) & 0x00FFFFFF) ^ crcTable[(crcTmp2 ^ (*ptr)) & 0xFF];
		ptr++;
	}
	return (crcTmp2 ^ 0xFFFFFFFF);
}

int cnt=0;
struct MBR *mbr[26];
struct super_sector *ss[26];
int slot_storage[26];

int hafs_load_fs(int storage)
{
    mbr[cnt] = (struct MBR *)read_disk(storage, 0, 1);
    if(mbr[cnt]->oem[0]!='H'||mbr[cnt]->oem[1]!='A'||mbr[cnt]->oem[2]!='F'||mbr[cnt]->oem[3]!='S')
    {
        return -1;
    }
    
    if(mbr[cnt]->version != 0x1) 
    {
    	return -2;
	}

    ss[cnt] = (struct super_sector *)read_disk(storage, 1, 1);
    if(ss[cnt]->identifier[0]!='H'||ss[cnt]->identifier[1]!='A'||ss[cnt]->identifier[2]!='F'||ss[cnt]->identifier[3]!='S')
    {
        return -1;
    }

    unsigned int sum=CRC32((unsigned char *)ss[cnt], sizeof(struct super_sector)-4);
    if(sum!=ss[cnt]->crc)
    {
        return -3;
    }

    slot_storage[cnt] = storage;

    return cnt++;
}

int hafs_make_fs(int storage, unsigned long long size, unsigned int block_size, unsigned int inode_number)
{
    if(block_size != 1024 && block_size != 2048 && block_size != 4096) return -1;
    if(inode_number % (block_size / sizeof(struct inode))) return -1;
    if(size % block_size) return -1;
    if(((block_size == 1024 || block_size == 2048) && inode_number > 4096) || (block_size == 4096 && inode_number > 20480)) return -1;
    if(size < block_size * 1024) return -2;

    struct MBR _mbr;
    memset(&_mbr, 0, sizeof(_mbr));
    _mbr.oem[0]='H';_mbr.oem[1]='A';_mbr.oem[2]='F';_mbr.oem[3]='S';
    _mbr.oem[4]=' ';_mbr.oem[5]=' ';_mbr.oem[6]=' ';_mbr.oem[7]=' ';
    _mbr.sector_size = 0x200;
    _mbr.block_sector = block_size / 0x200;
    _mbr.type = get_disk_type(storage);
    _mbr.sig = 0x00800080;
    _mbr.sector_number = size >> 9;
    _mbr.version = 0x1;
    _mbr.super_sector_start = 1 + RESERVE_SECTOR;

    char buf[512];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, &_mbr, sizeof(_mbr));

    write_disk(storage, 0, 1, buf);

    struct super_sector _ss;
    memset(&_ss, 0, sizeof(_ss));

    unsigned int seg_number = size / block_size / SEG_BLOCK;
    
    if(seg_number == 0) seg_number++;

    _ss.identifier[0]='H',_ss.identifier[1]='A',_ss.identifier[2]='F',_ss.identifier[3]='S';
    _ss.size = size;
    _ss.block_size = block_size;
    _ss.block_map_start = _mbr.super_sector_start + 1;
    _ss.block_map_size = round(seg_number, 8 * 0x200);
    _ss.inode_map_start = _ss.block_map_start + _ss.block_map_size;
    _ss.inode_map_size = _ss.block_map_size;
    _ss.zero_seg_start = round(_ss.inode_map_start + _ss.inode_map_size, block_size / 0x200);
    _ss.root_inode = 0;
    _ss.type = FS_TYPE_HD;
    _ss.inode_per_seg = inode_number;
    _ss.seg_number = seg_number;

    _ss.crc = CRC32((unsigned char *)&_ss, sizeof(struct super_sector)-4);

    memset(buf, 0, sizeof(buf));
    memcpy(buf, &_ss, sizeof(_ss));

    write_disk(storage, _mbr.super_sector_start, 1, buf);
    
    memset(buf, 0, sizeof(buf));
    
    write_disk(storage, _ss.block_map_start, _ss.block_map_size, buf);
    write_disk(storage, _ss.inode_map_start, _ss.inode_map_size, buf);

    struct seg_super_sector sss;
    sss.identifier[0]='H',sss.identifier[1]='A',sss.identifier[2]='F',sss.identifier[3]='S';
    if(seg_number != 1)
    {
        sss.block_number = SEG_BLOCK;
    }else{
        sss.block_number = size / block_size;
    }
    sss.block_map_rel_start = _ss.zero_seg_start * block_size / 0x200 + 1;
    sss.inode_map_rel_start = _ss.zero_seg_start * block_size / 0x200 + 2;
    if(block_size == 1024) sss.inode_rel_start = _ss.zero_seg_start * block_size / 0x200 + 4;
    else if(block_size == 2048) sss.inode_rel_start = _ss.zero_seg_start * block_size / 0x200 + 4;
    else sss.inode_rel_start = _ss.zero_seg_start * block_size / 0x200 + 8;
    sss.block_left = sss.block_number - round(sss.inode_rel_start + inode_number * sizeof(struct inode) / 0x200, block_size / 0x200);
    sss.inode_left = inode_number;

    sss.crc = CRC32((unsigned char *)&sss, sizeof(struct seg_super_sector)-4);

    memset(buf, 0, sizeof(buf));
    memcpy(buf, &sss, sizeof(sss));

    write_disk(storage, _ss.zero_seg_start * block_size / 0x200, 1, buf);

    memset(buf, 0, sizeof(buf));
    for(int k=0;k<sss.block_number - sss.block_left;k++)
    {
        bit_map_set(buf,k);
    }
    write_disk(storage, sss.block_map_rel_start, 1, buf);

    memset(buf, 0, sizeof(buf));
    bit_map_set(buf,0);
    write_disk(storage, sss.inode_map_rel_start, 1, buf);
    
    struct inode root;
    memset(&root, 0, sizeof(root));
    root.type = INODE_PRESENT | INODE_DIR;

    memset(buf, 0, sizeof(buf));
    memcpy(buf, &root, sizeof(root));

    write_disk(storage, sss.inode_rel_start, 1, buf);

    for(int i=1;i<seg_number;i++)
    {
        struct seg_super_sector sss;
        sss.identifier[0]='H',sss.identifier[1]='A',sss.identifier[2]='F',sss.identifier[3]='S';
        if(i == seg_number - 1)
            sss.block_number = size / block_size - 1LL * (seg_number - 1) * SEG_BLOCK;
        else
            sss.block_number = SEG_BLOCK;
        sss.block_map_rel_start = 1;
        sss.inode_map_rel_start = 2;
        if(block_size == 1024) sss.inode_rel_start = 4;
        else if(block_size == 2048) sss.inode_rel_start = 4;
        else sss.inode_rel_start = 8;
        sss.block_left = sss.block_number - round(sss.inode_rel_start + inode_number * sizeof(struct inode) / 0x200, block_size / 0x200);
        sss.inode_left = inode_number;

        sss.crc = CRC32((unsigned char *)&sss, sizeof(struct seg_super_sector)-4);

        memset(buf, 0, sizeof(buf));
        memcpy(buf, &sss, sizeof(sss));

        write_disk(storage, 1LL * i * SEG_BLOCK * block_size / 0x200, 1, buf);

        memset(buf, 0, sizeof(buf));
        for(int k=0;k<sss.block_number - sss.block_left;k++)
        {
            bit_map_set(buf,k);
        }
        write_disk(storage, 1LL * i * SEG_BLOCK * block_size / 0x200 + 1, 1, buf);
    }

    return 0;
}

struct inode *hafs_get_inode(int slot, unsigned int inode)
{
    if(slot >= cnt) return NULL;
    if(inode >= 1LL * ss[slot]->inode_per_seg * ss[slot]->seg_number) return NULL;
    unsigned int inode_seg = inode / ss[slot]->inode_per_seg;
    unsigned int inode_in_seg = inode % ss[slot]->inode_per_seg;
    unsigned int inode_in_seg_sector = inode_in_seg / (0x200 / sizeof(struct inode));
    unsigned int inode_in_sector = inode_in_seg % (0x200 / sizeof(struct inode));
    
    struct seg_super_sector *sss;
    unsigned long long seg_start = 0;
    if(inode_seg == 0)
    {
        sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start * ss[slot]->block_size / 0x200, 1);
        seg_start = 0;
    }else{
        sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * inode_seg, 1);
        seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * inode_seg;
    }

    struct inode *node = (struct inode *)(read_disk(slot_storage[slot], seg_start + sss->inode_rel_start + inode_in_seg_sector, 1) + inode_in_sector * sizeof(struct inode));
    if(node->type & INODE_PRESENT == 0) return NULL;
    return node;
}

int hafs_set_inode(int slot, unsigned int inode, struct inode *node)
{
    if(slot >= cnt) return -1;
    if(inode >= 1LL * ss[slot]->inode_per_seg * ss[slot]->seg_number) return -1;
    unsigned int inode_seg = inode / ss[slot]->inode_per_seg;
    unsigned int inode_in_seg = inode % ss[slot]->inode_per_seg;
    unsigned int inode_in_seg_sector = inode_in_seg / (0x200 / sizeof(struct inode));
    unsigned int inode_in_sector = inode_in_seg % (0x200 / sizeof(struct inode));

    struct seg_super_sector *sss;
    unsigned long long seg_start = 0;
    if(inode_seg == 0)
    {
        sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start * ss[slot]->block_size / 0x200, 1);
        seg_start = 0;
    }else{
        sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * inode_seg, 1);
        seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * inode_seg;
    }

    char *point = read_disk(slot_storage[slot], seg_start + sss->inode_rel_start + inode_in_seg_sector, 1);
    memcpy(point + inode_in_sector * sizeof(struct inode), node, sizeof(struct inode));
    write_disk(slot_storage[slot], seg_start + sss->inode_rel_start + inode_in_seg_sector, 1, point);
    
    return 0;
}

char *hafs_get_block(int slot, unsigned int block_number)
{
    if(slot >= cnt) return NULL;
    return read_disk(slot_storage[slot], 1LL * block_number * ss[slot]->block_size / 0x200, ss[slot]->block_size / 0x200);
}

int hafs_put_block(int slot, unsigned int block_number, const void *buf)
{
    if(slot >= cnt) return -1;
    return write_disk(slot_storage[slot], 1LL * block_number * ss[slot]->block_size / 0x200, ss[slot]->block_size / 0x200, buf);
}

char *hafs_get_file_data(int slot, unsigned int inode, unsigned int start_block, unsigned int block_number)
{
    if(slot >= cnt) return NULL;
    struct inode *node = hafs_get_inode(slot, inode);
    if(start_block + block_number > round(node->file_size,ss[slot]->block_size))
    {
        return NULL;
    }
    if(!block_number) return NULL;
    char *block = (char *)malloc(block_number * ss[slot]->block_size);
    int block_index = 0;
    int block_cnt = 0;
    if(start_block < 12)
    {
        char *chunk;
        for(int i=start_block;i<12;i++)
        {
            chunk = hafs_get_block(slot, node->direct[i]);
            memcpy((block + block_index * ss[slot]->block_size), chunk, ss[slot]->block_size);
            block_index++;
            if(block_index == block_number) return block;
        }
    }

    char *chunk;
    unsigned int *ind1,*ind2,*ind3;
    
    block_cnt = 12;

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int i=0;i<8;i++)
        {
            ind1 = (unsigned int *)hafs_get_block(slot, node->indirect_1[i]);
            for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
            {
                if(block_cnt < start_block)
				{
					block_cnt++;
					continue;
				}
	        	block_cnt++;
                chunk = hafs_get_block(slot, ind1[k]);
                memcpy((block + block_index * ss[slot]->block_size), chunk, ss[slot]->block_size);
                block_index++;
                if(block_index == block_number) return block;
            }
        }
    }
    
    block_cnt = 12 + 8 * ss[slot]->block_size / sizeof(unsigned int);

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int m=0;m<4;m++)
        {
            ind2 = (unsigned int *)hafs_get_block(slot, node->indirect_2[m]);
            for(int i=0;i<ss[slot]->block_size / sizeof(unsigned int);i++)
            {
                ind1 = (unsigned int *)hafs_get_block(slot, ind2[i]);
                for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
                {
                	if(block_cnt < start_block)
					{
						block_cnt++;
						continue;
					}
		        	block_cnt++;
					chunk = hafs_get_block(slot, ind1[k]);
                    memcpy((block + block_index * ss[slot]->block_size), chunk, ss[slot]->block_size);
                    block_index++;
                    if(block_index == block_number) return block;
                }
            }
        }
    }
    
    block_cnt = 12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int);

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int n=0;n<4;n++)
        {
            ind3 = (unsigned int *)hafs_get_block(slot, node->indirect_3[n]);
            for(int m=0;m<ss[slot]->block_size / sizeof(unsigned int);m++)
            {
                ind2 = (unsigned int *)hafs_get_block(slot, ind3[m]);
                for(int i=0;i<ss[slot]->block_size / sizeof(unsigned int);i++)
                {
                    ind1 = (unsigned int *)hafs_get_block(slot, ind2[i]);
                    for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
                    {
                    	if(block_cnt < start_block)
						{
							block_cnt++;
							continue;
						}
			        	block_cnt++;
                        chunk = hafs_get_block(slot, ind1[k]);
                        memcpy((block + block_index * ss[slot]->block_size), chunk, ss[slot]->block_size);
                        block_index++;
                        if(block_index == block_number) return block;
                    }
                }
            }
        }
    }

    return NULL;
}

int hafs_put_file_data(int slot, unsigned int inode, unsigned int start_block, unsigned int block_number, const char *buf)
{
    if(slot >= cnt) return -1;
    struct inode *node = hafs_get_inode(slot, inode);
    if(node == NULL) return -1;
    if(start_block + block_number > round(node->file_size,ss[slot]->block_size))
    {
        return -1;
    }
    int block_index = 0;
    int block_cnt = 0;
    if(start_block < 12)
    {
        const char *chunk;
        for(int i=start_block;i<12;i++)
        {
            chunk = buf + block_index * ss[slot]->block_size;
            hafs_put_block(slot, node->direct[i], chunk);
            block_index++;
            if(block_index == block_number) return 0;
        }
    }
    
    const char *chunk;
    unsigned int *ind1,*ind2,*ind3;
    
    block_cnt = 12;

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int i=0;i<8;i++)
        {
            ind1 = (unsigned int *)hafs_get_block(slot, node->indirect_1[i]);
            for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
            {
                if(block_cnt < start_block)
				{
					block_cnt++;
					continue;
				}
	        	block_cnt++;
                chunk = buf + block_index * ss[slot]->block_size;
                hafs_put_block(slot, ind1[k], chunk);
                block_index++;
                if(block_index == block_number) return 0;
            }
        }
    }
    
    block_cnt = 12 + 8 * ss[slot]->block_size / sizeof(unsigned int);

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int m=0;m<4;m++)
        {
            ind2 = (unsigned int *)hafs_get_block(slot, node->indirect_2[m]);
            for(int i=0;i<ss[slot]->block_size / sizeof(unsigned int);i++)
            {
                ind1 = (unsigned int *)hafs_get_block(slot, ind2[i]);
                for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
                {
                	if(block_cnt < start_block)
					{
						block_cnt++;
						continue;
					}
		        	block_cnt++;
                    chunk = buf + block_index * ss[slot]->block_size;
                    hafs_put_block(slot, ind1[k], chunk);
                    block_index++;
                    if(block_index == block_number) return 0;
                }
            }
        }
    }
    
    block_cnt = 12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int);

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int n=0;n<4;n++)
        {
            ind3 = (unsigned int *)hafs_get_block(slot, node->indirect_3[n]);
            for(int m=0;m<ss[slot]->block_size / sizeof(unsigned int);m++)
            {
                ind2 = (unsigned int *)hafs_get_block(slot, ind3[m]);
                for(int i=0;i<ss[slot]->block_size / sizeof(unsigned int);i++)
                {
                    ind1 = (unsigned int *)hafs_get_block(slot, ind2[i]);
                    for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
                    {
                    	if(block_cnt < start_block)
						{
							block_cnt++;
							continue;
						}
			        	block_cnt++;
                        chunk = buf + block_index * ss[slot]->block_size;
                        hafs_put_block(slot, ind1[k], chunk);
                        block_index++;
                        if(block_index == block_number) return 0;
                    }
                }
            }
        }
    }
    return 0;
}

unsigned int hafs_find_inode(int slot, const char *pathname, unsigned int len, unsigned int u_inode)      //pathname must be \xxxx\xxxx\xxxx\xxx.xxx
{
    if(slot >= cnt) return 0;
    if(len < 1) return 0;
    if(pathname[0] != '\\') return 0;
    int i;
    for(i=1;i<len;i++)
    {
        if(pathname[i] == '\\') break;
    }
    if(i==len||(i==len-1&&pathname[i] == '\\'))
    {
    	i--;
        if(pathname[i] == '\\')
        {
            i--;
        }
        struct inode *inode = hafs_get_inode(slot, u_inode);
        if(inode->file_size == 0) return 0;
        char *dir = hafs_get_file_data(slot, u_inode, 0, round(inode->file_size,ss[slot]->block_size));
        char *point_now = dir;
        unsigned int *next_record = (unsigned int *)point_now;
        while(*next_record != 0)
        {
            char *filename = point_now + 8;
            unsigned int len = *next_record - 8;
            if(len == i)
            {
                if(!memcmp(filename, pathname+1, len))
                {
                    return *(next_record+1);
                }
            }
            point_now += *next_record;
            next_record = (unsigned int *)point_now;
        }
        char *filename = point_now + 8;
        unsigned int len = inode->file_size - ((char *)next_record-dir) - 8;
        if(len == i)
        {
            if(!memcmp(filename, pathname+1, len))
            {
                return *(next_record+1);
            }
        }
    }else{
        i--;
        struct inode *inode = hafs_get_inode(slot, u_inode);
        if(inode->file_size == 0) return 0;
        char *dir = hafs_get_file_data(slot, u_inode, 0, round(inode->file_size,ss[slot]->block_size));
        char *point_now = dir;
        unsigned int *next_record = (unsigned int *)point_now;
        while(*next_record != 0)
        {
            char *filename = point_now + 8;
            unsigned int _len = *next_record - 8;
            if(_len == i)
            {
                if(!memcmp(filename, pathname + 1, _len))
                {
                    return hafs_find_inode(slot, pathname + 1 + _len, len-_len-1, *(next_record+1));
                }
            }
            point_now += *next_record;
            next_record = (unsigned int *)point_now;
        }
        char *filename = point_now + 8;
        unsigned int _len = inode->file_size - ((char *)next_record-dir) - 8;
        if(_len == i)
        {
            if(!memcmp(filename, pathname+1, _len))
            {
                return hafs_find_inode(slot, pathname + 1 + _len, len-_len-1, *(next_record+1));
            }
        }
    }
    
    return 0;
}

unsigned int hafs_alloc_block(int slot)
{
    if(slot >= cnt) return 0;
    
    char *block_bitmap = read_disk(slot_storage[slot], ss[slot]->block_map_start, ss[slot]->block_map_size);
    
    int seg;
    if((seg = bit_map_find(block_bitmap, ss[slot]->seg_number)) == -1) return 0;
    
    struct seg_super_sector *sss;
    unsigned long long seg_start = 0;
    if(seg == 0)
    {
        sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start * ss[slot]->block_size / 0x200, 1);
        seg_start = 0;
    }else{
        sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * seg, 1);
        seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * seg;
    }
    
    char *seg_block_bitmap = read_disk(slot_storage[slot], seg_start + sss->block_map_rel_start, 1);

    int block;
    if((block = bit_map_find(seg_block_bitmap, SEG_BLOCK)) == -1) return 0;

    bit_map_set(seg_block_bitmap,block);
    sss->block_left--;
    write_disk(slot_storage[slot], seg_start + sss->block_map_rel_start, 1, seg_block_bitmap);
    
    sss->crc = CRC32((unsigned char *)sss, sizeof(struct seg_super_sector)-4);

    if(seg == 0)
    {
        write_disk(slot_storage[slot], ss[slot]->zero_seg_start * ss[slot]->block_size / 0x200, 1, sss);
    }else{
        write_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * seg, 1, sss);
    }

    if(sss->block_left == 0)
    {
        bit_map_set(block_bitmap, seg);
        write_disk(slot_storage[slot], ss[slot]->block_map_start, ss[slot]->block_map_size, block_bitmap);
    }

    return seg * SEG_BLOCK + block;
}

unsigned int *hafs_alloc_blocks(int slot, unsigned int block_number)
{
    if(slot >= cnt) return NULL;
    
    char *block_bitmap = read_disk(slot_storage[slot], ss[slot]->block_map_start, ss[slot]->block_map_size);
    
    int t=0, num=0;
    while(((t = bit_map_find_mask(block_bitmap, ss[slot]->seg_number, t)) != -1))
    {
        struct seg_super_sector *sss;
        unsigned long long seg_start = 0;
        if(t == 0)
        {
            sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start * ss[slot]->block_size / 0x200, 1);
            seg_start = 0;
        }else{
            sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * t, 1);
            seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * t;
        }
        num+=sss->block_left;
        if(num>=block_number) break;
    }

    if(num<block_number) return NULL;

    unsigned int *blocks = (unsigned int *)malloc(block_number * 4);
    int point = 0;
    while(block_number)
    {
        int seg;
        if((seg = bit_map_find(block_bitmap, ss[slot]->seg_number)) == -1) return NULL;
        
        struct seg_super_sector *sss;
        unsigned long long seg_start = 0;
        if(seg == 0)
        {
            sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start * ss[slot]->block_size / 0x200, 1);
            seg_start = 0;
        }else{
            sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * seg, 1);
            seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * seg;
        }
        char *seg_block_bitmap = read_disk(slot_storage[slot], seg_start + sss->block_map_rel_start, 1);
        
        while(block_number && sss->block_left)
        {
            int block;
            if((block = bit_map_find(seg_block_bitmap, sss->block_number)) == -1) break;
            
            bit_map_set(seg_block_bitmap,block);
            sss->block_left--;
            blocks[point++] = seg * SEG_BLOCK + block;
            block_number--;
        }

        write_disk(slot_storage[slot], seg_start + sss->block_map_rel_start, 1, seg_block_bitmap);
        
        sss->crc = CRC32((unsigned char *)sss, sizeof(struct seg_super_sector)-4);

        if(seg == 0)
        {
            write_disk(slot_storage[slot], ss[slot]->zero_seg_start * ss[slot]->block_size / 0x200, 1, sss);
        }else{
            write_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * seg, 1, sss);
        }
        if(sss->block_left == 0)
        {
            bit_map_set(block_bitmap, seg);
            write_disk(slot_storage[slot], ss[slot]->block_map_start, ss[slot]->block_map_size, block_bitmap);
        }
    }

    return blocks;
}

unsigned int hafs_alloc_inode(int slot)
{
    if(slot >= cnt) return 0;
    
    char *inode_bitmap = read_disk(slot_storage[slot], ss[slot]->inode_map_start, ss[slot]->inode_map_size);
    
    int seg;
    if((seg = bit_map_find(inode_bitmap, ss[slot]->seg_number)) == -1) return 0;
    
    struct seg_super_sector *sss;
    unsigned long long seg_start = 0;
    if(seg == 0)
    {
        sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start * ss[slot]->block_size / 0x200, 1);
        seg_start = 0;
    }else{
        sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * seg, 1);
        seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * seg;
    }
    
    char *seg_inode_bitmap = read_disk(slot_storage[slot], seg_start + sss->inode_map_rel_start, sss->inode_rel_start - sss->inode_map_rel_start);

    int inode;
    if((inode = bit_map_find(seg_inode_bitmap, ss[slot]->inode_per_seg)) == -1) return 0;

    bit_map_set(seg_inode_bitmap,inode);
    sss->inode_left--;
    write_disk(slot_storage[slot], seg_start + sss->inode_map_rel_start, 1, seg_inode_bitmap);
    
    sss->crc = CRC32((unsigned char *)sss, sizeof(struct seg_super_sector)-4);

    if(seg == 0)
    {
        write_disk(slot_storage[slot], ss[slot]->zero_seg_start * ss[slot]->block_size / 0x200, 1, sss);
    }else{
        write_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * seg, 1, sss);
    }

    if(sss->inode_left == 0)
    {
        bit_map_set(inode_bitmap, seg);
        write_disk(slot_storage[slot], ss[slot]->inode_map_start, ss[slot]->inode_map_size, inode_bitmap);
    }

    struct inode node;
    memset(&node, 0, sizeof(node));
    node.type = INODE_PRESENT;
    hafs_set_inode(slot, seg * ss[slot]->inode_per_seg + inode, &node);

    return seg * ss[slot]->inode_per_seg + inode;
}

int hafs_free_block(int slot, unsigned int block_number)
{
    int t = block_number / SEG_BLOCK;
    if(t >= ss[slot]->seg_number) t=ss[slot]->seg_number;

    struct seg_super_sector *sss;
    unsigned long long seg_start = 0;
    if(t==0)
    {
        sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start * ss[slot]->block_size / 0x200, 1);
        seg_start = 0;
    }else{
        sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * t, 1);
        seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * t;
    }

    unsigned int block_in_seg = block_number % sss->block_number;
    if(block_in_seg < (sss->inode_rel_start + ss[slot]->inode_per_seg / (0x200 / sizeof(struct inode))) * 0x200 / ss[slot]->block_size) return -1;

    char *seg_block_bitmap = read_disk(slot_storage[slot], seg_start + sss->block_map_rel_start, 1);
    
    if(bit_map_get(seg_block_bitmap, block_in_seg) == 0) return -1;

    bit_map_unset(seg_block_bitmap, block_in_seg);
    sss->block_left++;
    write_disk(slot_storage[slot], seg_start + sss->block_map_rel_start, 1, seg_block_bitmap);
    
    sss->crc = CRC32((unsigned char *)sss, sizeof(struct seg_super_sector)-4);
    
    if(t == 0)
    {
        write_disk(slot_storage[slot], ss[slot]->zero_seg_start * ss[slot]->block_size / 0x200, 1, sss);
    }else{
        write_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * t, 1, sss);
    }

    if(sss->block_left == 1)
    {
        char *block_bitmap = read_disk(slot_storage[slot], ss[slot]->block_map_start, ss[slot]->block_map_size);
        bit_map_unset(block_bitmap, t);
        write_disk(slot_storage[slot], ss[slot]->block_map_start, ss[slot]->block_map_size, block_bitmap);
    }

    return 0;
}

int hafs_free_inode(int slot, unsigned int inode_number)
{
    int t = inode_number / ss[slot]->inode_per_seg;
    if(t >= ss[slot]->seg_number) t=ss[slot]->seg_number;

    struct seg_super_sector *sss;
    unsigned long long seg_start = 0;
    if(t==0)
    {
        sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start * ss[slot]->block_size / 0x200, 1);
        seg_start = 0;
    }else{
        sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * t, 1);
        seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * t;
    }

    unsigned int inode_in_seg = inode_number % ss[slot]->inode_per_seg;

    char *seg_inode_bitmap = read_disk(slot_storage[slot], seg_start + sss->inode_map_rel_start, 1);
    
    if(!bit_map_get(seg_inode_bitmap, inode_in_seg)) return -1;

    bit_map_unset(seg_inode_bitmap, inode_in_seg);
    sss->inode_left++;
    write_disk(slot_storage[slot], seg_start + sss->inode_map_rel_start, 1, seg_inode_bitmap);
    
    sss->crc = CRC32((unsigned char *)sss, sizeof(struct seg_super_sector)-4);
    
    if(t == 0)
    {
        write_disk(slot_storage[slot], ss[slot]->zero_seg_start * ss[slot]->block_size / 0x200, 1, sss);
    }else{
        write_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * t, 1, sss);
    }

    if(sss->inode_left == 1)
    {
        char *inode_bitmap = read_disk(slot_storage[slot], ss[slot]->inode_map_start, ss[slot]->inode_map_size);
        bit_map_unset(inode_bitmap, t);
        write_disk(slot_storage[slot], ss[slot]->inode_map_start, ss[slot]->inode_map_size, inode_bitmap);
    }

    return 0;
}

unsigned int _calc_block_number(unsigned int block_size, int x)
{
    unsigned bs = block_size / sizeof(unsigned int), t=x;
    if(x<=12) return t;
    x-=12;
    if(x<=8*bs) return t+round(x,bs);
    x-=8*bs;
    if(x<=4*bs*bs) return t+round(x,bs)+round(x,bs*bs);
    x-=4*bs*bs;
    return  t+round(x,bs)+round(x,bs*bs)+round(x,bs*bs*bs);
}

int hafs_file_alloc_block(int slot, int inode, int add_number)
{
    if(slot >= cnt) return -1;
    
    struct inode *node = hafs_get_inode(slot, inode);
    if(node == NULL) return -1;
    char *block_bitmap = read_disk(slot_storage[slot], ss[slot]->block_map_start, ss[slot]->block_map_size);
    
    int t = 0, num=0, tot =  _calc_block_number(ss[slot]->block_size, round(node->file_size, ss[slot]->block_size) + add_number) - _calc_block_number(ss[slot]->block_size, add_number);
	while(((t = bit_map_find_mask(block_bitmap, ss[slot]->seg_number, t)) != -1))
    {
        struct seg_super_sector *sss;
        unsigned long long seg_start = 0;
        if(t == 0)
        {
            sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start * ss[slot]->block_size / 0x200, 1);
            seg_start = 0;
        }else{
            sss = (struct seg_super_sector *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * t, 1);
            seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * t;
        }
        num+=sss->block_left;
        if(num>=tot) break;
    }

    if(num<tot) return 0;

    unsigned int *blocks = hafs_alloc_blocks(slot, add_number);
    if(blocks == NULL) return -1;

    unsigned int start_block = round(node->file_size, ss[slot]->block_size);
    unsigned int block_index = 0;
    unsigned int block_cnt = 0;
    if(start_block < 12)
    {
        for(int i=0;i<12;i++)
        {
        	if(block_cnt < start_block)
			{
				block_cnt++;
				continue;
			}
            node->direct[i] = blocks[block_index];
            block_index++;
            if(block_index == add_number)
            {
                hafs_set_inode(slot, inode, node);
                return 0;
            }
            block_cnt++;
        }
    }
    
    block_cnt = 12;
    
    char *chunk;
    unsigned int *ind1,*ind2,*ind3;

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int i=0;i<8;i++)
        {
            if(!node->indirect_1[i])
            {
                node->indirect_1[i] = hafs_alloc_block(slot);
                if(!node->indirect_1[i]) return -1;
                ind1 = (unsigned int *)malloc(ss[slot]->block_size);
                memset(ind1, 0, ss[slot]->block_size);
            }else ind1 = (unsigned int *)hafs_get_block(slot, node->indirect_1[i]);
            for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
            {
//                if(12 + (i+1)*k < start_block) continue;
//				if(ind1[k]) continue;
				if(block_cnt < start_block)
				{
					block_cnt++;
					continue;
				}
                ind1[k] = blocks[block_index];
                block_index++;
                if(block_index == add_number)
                {
                    hafs_put_block(slot, node->indirect_1[i], ind1);
                    hafs_set_inode(slot, inode, node);
                    return 0;
                }
                block_cnt++;
            }
            hafs_put_block(slot, node->indirect_1[i], ind1);
        }
    }
    
    block_cnt = 12 + 8 * ss[slot]->block_size / sizeof(unsigned int);

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int m=0;m<4;m++)
        {
            if(!node->indirect_2[m])
            {
                node->indirect_2[m] = hafs_alloc_block(slot);
                if(!node->indirect_2[m]) return -1;
                ind2 = (unsigned int *)malloc(ss[slot]->block_size);
                memset(ind2, 0, ss[slot]->block_size);
            }else ind2 = (unsigned int *)hafs_get_block(slot, node->indirect_2[m]);
            for(int i=0;i<ss[slot]->block_size / sizeof(unsigned int);i++)
            {
                if(!ind2[i])
                {
                    ind2[i] = hafs_alloc_block(slot);
                    if(!ind2[i]) return -1;
                    ind1 = (unsigned int *)malloc(ss[slot]->block_size);
                    memset(ind1, 0, ss[slot]->block_size);
                }else ind1 = (unsigned int *)hafs_get_block(slot, ind2[i]);
                for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
                {
//                    if(12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + (m+1)*(i+1)*k < start_block) continue;
//					if(ind1[k]) continue;
					if(block_cnt < start_block)
					{
						block_cnt++;
						continue;
					}
					ind1[k] = blocks[block_index];
                    block_index++;
                    if(block_index == add_number)
                    {
                        hafs_put_block(slot, node->indirect_2[m], ind2);
                        hafs_put_block(slot, ind2[i], ind1);
                        hafs_set_inode(slot, inode, node);
                        return 0;
                    }
                    block_cnt++;
                }
                hafs_put_block(slot, ind2[i], ind1);
            }
            hafs_put_block(slot, node->indirect_2[m], ind2);
        }
    }
    
    block_cnt = 12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int);

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int n=0;n<4;n++)
        {
            if(!node->indirect_3[n])
            {
                node->indirect_3[n] = hafs_alloc_block(slot);
                if(!node->indirect_3[n]) return -1;
                ind3 = (unsigned int *)malloc(ss[slot]->block_size);
                memset(ind3, 0, ss[slot]->block_size);
            }else ind3 = (unsigned int *)hafs_get_block(slot, node->indirect_3[n]);
            for(int m=0;m<ss[slot]->block_size / sizeof(unsigned int);m++)
            {
                if(!ind3[m])
                {
                    ind3[m] = hafs_alloc_block(slot);
                    if(!ind3[m]) return -1;
                    ind2 = (unsigned int *)malloc(ss[slot]->block_size);
                    memset(ind2, 0, ss[slot]->block_size);
                }else ind2 = (unsigned int *)hafs_get_block(slot, ind3[m]);
                for(int i=0;i<ss[slot]->block_size / sizeof(unsigned int);i++)
                {
                    if(!ind2[i])
                    {
                        ind2[i] = hafs_alloc_block(slot);
                        if(!ind2[i]) return -1;
                        ind1 = (unsigned int *)malloc(ss[slot]->block_size);
                        memset(ind1, 0, ss[slot]->block_size);
                    }else ind1 = (unsigned int *)hafs_get_block(slot, ind2[i]);
                    for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
                    {
//                        if(12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int) + (n+1)*(m+1)*(i+1)*k < start_block) continue;
                        if(ind1[k]) continue;
						ind1[k] = blocks[block_index];
                        block_index++;
                        if(block_index == add_number)
                        {
                            hafs_put_block(slot, node->indirect_3[n], ind3);
                            hafs_put_block(slot, ind3[m], ind2);
                            hafs_put_block(slot, ind2[i], ind1);
                            hafs_set_inode(slot, inode, node);
                            return 0;
                        }
                    }
                    hafs_put_block(slot, ind2[i], ind1);
                }
                hafs_put_block(slot, ind3[m], ind2);
            }
            hafs_put_block(slot, node->indirect_3[n], ind3);
        }
    }

    return 0;
}

int hafs_file_free_block(int slot, int inode, int start_block)
{
    if(slot >= cnt) return -1;
    
    struct inode *node = hafs_get_inode(slot, inode);
    if(node == NULL) return -1;
    
    if(start_block >= round(node->file_size, ss[slot]->block_size)) return -1;

    int block_number = round(node->file_size, ss[slot]->block_size) - start_block;
    int block_index = 0;
    int block_cnt = 0;
    if(start_block < 12)
    {
        for(int i=start_block;i<12;i++)
        {
        	if(block_cnt < start_block)
			{
				block_cnt++;
				continue;
			}
        	block_cnt++;
            hafs_free_block(slot, node->direct[i]);
            node->direct[i] = 0;
            block_index++;
            if(block_index == block_number)
            {
                hafs_set_inode(slot, inode, node);
                return 0;
            }
        }
    }
    
    block_cnt = 12;
    
    char *chunk;
    unsigned int *ind1,*ind2,*ind3;

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int i=0;i<8;i++)
        {
            if(!node->indirect_1[i])
            {
                continue;
            }else ind1 = (unsigned int *)hafs_get_block(slot, node->indirect_1[i]);
            for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
            {
                if(block_cnt < start_block)
				{
					block_cnt++;
					continue;
				}
	        	block_cnt++;
				hafs_free_block(slot, ind1[k]);
                ind1[k]=0;
                block_index++;
                if(block_index == block_number)
                {
                    hafs_put_block(slot, node->indirect_1[i], ind1);
                    hafs_set_inode(slot, inode, node);
                    return 0;
                }
            }
            int res=0;
            for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
            {
                res+=(ind1[k]!=0);
            }
            if(res)
            	hafs_put_block(slot, node->indirect_1[i], ind1);
            else
			{
            	hafs_free_block(slot, node->indirect_1[i]);
            	node->indirect_1[i] = 0;
			}
        }
    }
    
    block_cnt = 12 + 8 * ss[slot]->block_size / sizeof(unsigned int);

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int m=0;m<4;m++)
        {
            if(!node->indirect_2[m])
            {
                continue;
            }else ind2 = (unsigned int *)hafs_get_block(slot, node->indirect_2[m]);
            for(int i=0;i<ss[slot]->block_size / sizeof(unsigned int);i++)
            {
                if(!ind2[i])
                {
                    continue;
                }else ind1 = (unsigned int *)hafs_get_block(slot, ind2[i]);
                for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
                {
//                    if(12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + (m+1)*(i+1)*k < start_block) continue;
                    if(block_cnt < start_block)
					{
						block_cnt++;
						continue;
					}
		        	block_cnt++;
					hafs_free_block(slot, ind1[k]);
                    ind1[k]=0;
                    block_index++;
                    if(block_index == block_number)
                    {
                        hafs_put_block(slot, node->indirect_2[m], ind2);
                        hafs_put_block(slot, ind2[i], ind1);
                        hafs_set_inode(slot, inode, node);
                        return 0;
                    }
                }
                int res=0;
	            for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
	            {
	                res+=(ind1[k]!=0);
	            }
	            if(res)
	            	hafs_put_block(slot, ind2[i], ind1);
	            else
				{
	            	hafs_free_block(slot, ind2[i]);
	            	ind2[i] = 0;
				}
            }
            int res=0;
            for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
            {
                res+=(ind2[k]!=0);
            }
            if(res)
            	hafs_put_block(slot, node->indirect_2[m], ind2);
            else
			{
            	hafs_free_block(slot, node->indirect_2[m]);
            	node->indirect_2[m] = 0;
			}
        }
    }
    
    block_cnt = 12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int);

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int n=0;n<4;n++)
        {
            if(!node->indirect_3[n])
            {
                continue;
            }else ind3 = (unsigned int *)hafs_get_block(slot, node->indirect_3[n]);
            for(int m=0;m<ss[slot]->block_size / sizeof(unsigned int);m++)
            {
                if(!ind3[m])
                {
                    continue;
                }else ind2 = (unsigned int *)hafs_get_block(slot, ind3[m]);
                for(int i=0;i<ss[slot]->block_size / sizeof(unsigned int);i++)
                {
                    if(!ind2[i])
                    {
                        continue;
                    }else ind1 = (unsigned int *)hafs_get_block(slot, ind2[i]);
                    for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
                    {
//                        if(12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int) + (n+1)*(m+1)*(i+1)*k < start_block) continue;
                        if(block_cnt < start_block)
						{
							block_cnt++;
							continue;
						}
			        	block_cnt++;
						hafs_free_block(slot, ind1[k]);
                        ind1[k]=0;
                        block_index++;
                        if(block_index == block_number)
                        {
                            hafs_put_block(slot, node->indirect_3[n], ind3);
                            hafs_put_block(slot, ind3[m], ind2);
                            hafs_put_block(slot, ind2[i], ind1);
                            hafs_set_inode(slot, inode, node);
                            return 0;
                        }
                    }
                    int res=0;
		            for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
		            {
		                res+=(ind1[k]!=0);
		            }
		            if(res)
		            	hafs_put_block(slot, ind2[i], ind1);
		            else
					{
		            	hafs_free_block(slot, ind2[i]);
		            	ind2[i] = 0;
					}
                }
                int res=0;
	            for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
	            {
	                res+=(ind2[k]!=0);
	            }
	            if(res)
	            	hafs_put_block(slot, ind3[m], ind2);
	            else
				{
	            	hafs_free_block(slot, ind3[m]);
	            	ind3[m] = 0;
				}
            }
            int res=0;
            for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
            {
                res+=(ind3[k]!=0);
            }
            if(res)
            	hafs_put_block(slot, node->indirect_3[n], ind3);
            else
			{
            	hafs_free_block(slot, node->indirect_3[n]);
            	node->indirect_3[n] = 0;
			}
        }
    }

    return 0;
}

unsigned int hafs_create_file(int slot, const char *path, unsigned int pathlen, const char *filename, unsigned int namelen)
{
    if(slot >= cnt) return 0;
    if(namelen > 65536) return 0; 

    int fa_inode;
    if(pathlen==1&&path[0]=='\\') fa_inode = ss[slot]->root_inode;
    else if((fa_inode = hafs_find_inode(slot, path, pathlen, ss[slot]->root_inode)) == 0) return 0;

    struct inode *inode = hafs_get_inode(slot, fa_inode);
    if(inode->type & INODE_DIR == 0) return 0;
    if(inode->file_size)
    {
        char *dir_entry = (char *)malloc(round(inode->file_size+4+4+namelen, ss[slot]->block_size) * ss[slot]->block_size);
        memset(dir_entry, 0, round(inode->file_size+4+4+namelen, ss[slot]->block_size) * ss[slot]->block_size);
		char *dir = hafs_get_file_data(slot, fa_inode, 0, round(inode->file_size,ss[slot]->block_size));
        memcpy(dir_entry, dir, inode->file_size);
        char *point_now = dir_entry;
        unsigned int *next_record = (unsigned int *)point_now;
        while(*next_record != 0)
        {
            char *fname = point_now + 8;
            unsigned int len = *next_record - 8;
            if(len == namelen)
            {
                if(!memcmp(fname, filename, len))
                {
                    return 0;
                }
            }
            point_now += *next_record;
            next_record = (unsigned int *)point_now;
        }
        char *fname = point_now + 8;
        unsigned int len = inode->file_size-((char *)next_record-dir_entry) - 8;
        if(len == namelen)
        {
            if(!memcmp(fname, filename, len))
            {
                return 0;
            }
        }
        
        if(round(inode->file_size+4+4+namelen, ss[slot]->block_size) > round(inode->file_size, ss[slot]->block_size))
        {
            if(hafs_file_alloc_block(slot, fa_inode, round(inode->file_size+4+4+namelen, ss[slot]->block_size) - round(inode->file_size, ss[slot]->block_size))) return 0;
        }

        unsigned int new_inode = hafs_alloc_inode(slot);
        if(!new_inode) return 0;
        *next_record = inode->file_size-((char *)next_record-dir_entry);
        point_now = dir_entry+inode->file_size;
        *(unsigned int *)(point_now) = 0;
        *(unsigned int *)(point_now + 4) = new_inode;
        memcpy(point_now + 8, filename, namelen);

        hafs_put_file_data(slot, fa_inode, 0, round(inode->file_size+4+4+namelen, ss[slot]->block_size), dir_entry);

        struct inode node;
        memset(&node, 0, sizeof(node));
        node.type = INODE_PRESENT | INODE_FILE;
        hafs_set_inode(slot, new_inode, &node);

        inode = hafs_get_inode(slot, fa_inode);
        inode->file_size += 4+4+namelen;
        hafs_set_inode(slot, fa_inode, inode);

        return new_inode;
    }else{
        if(hafs_file_alloc_block(slot, fa_inode, round(4+4+namelen, ss[slot]->block_size))) return 0;
        char *dir_entry = (char *)malloc(round(4+4+namelen, ss[slot]->block_size) * ss[slot]->block_size);
        memset(dir_entry, 0, round(4+4+namelen, ss[slot]->block_size) * ss[slot]->block_size);
        unsigned int new_inode = hafs_alloc_inode(slot);
        if(!new_inode) return 0;
        *((unsigned int *)dir_entry) = 0;
        *((unsigned int *)(dir_entry + 4)) = new_inode;
        memcpy(dir_entry + 8, filename, namelen);
        
        inode = hafs_get_inode(slot, fa_inode);
        inode->file_size = 4+4+namelen;
        hafs_set_inode(slot, fa_inode, inode);

        hafs_put_file_data(slot, fa_inode, 0, round(4+4+namelen, ss[slot]->block_size), dir_entry);

        struct inode node;
        memset(&node, 0, sizeof(node));
        node.type = INODE_PRESENT | INODE_FILE;
        hafs_set_inode(slot, new_inode, &node);

        return new_inode;
    }
    return 0;
}

char *hafs_read_file(int slot, const char *file_name, unsigned int namelen, unsigned long long pos, unsigned long long size)
{
    if(slot >= cnt) return NULL;

    unsigned int inode = hafs_find_inode(slot, file_name, namelen, ss[slot]->root_inode);
    if(!inode) return NULL;

    struct inode *node = hafs_get_inode(slot, inode);
    if(node == NULL) return NULL;
    if(pos + size > node->file_size) return NULL;

    unsigned int block_start = pos / ss[slot]->block_size, block_number = round(pos + size, ss[slot]->block_size);
    char *tmp = hafs_get_file_data(slot, inode, block_start, block_number - block_start);
    if(tmp == NULL) return NULL;
    char *res = (char *)malloc(size);
    memcpy(res, tmp + pos - block_start * ss[slot]->block_size, size);
    return res;
}

int hafs_write_file(int slot, const char *file_name, unsigned int namelen, unsigned long long pos, unsigned long long size, const char *buf)
{
    if(slot >= cnt) return -1;

    unsigned int inode = hafs_find_inode(slot, file_name, namelen, ss[slot]->root_inode);
    if(!inode) return -1;

    struct inode *node = hafs_get_inode(slot, inode);
    if(node == NULL) return -1;
    if(pos > node->file_size) return -1;
    if(round(node->file_size + size, ss[slot]->block_size) - round(node->file_size, ss[slot]->block_size))
    {
        if(hafs_file_alloc_block(slot, inode, round(node->file_size + size, ss[slot]->block_size) - round(node->file_size, ss[slot]->block_size)) == -1) return -1;
    }

    unsigned int block_start = pos / ss[slot]->block_size, block_number = round(pos + size, ss[slot]->block_size);
    char *res = (char *)malloc(round(node->file_size + size, ss[slot]->block_size) * ss[slot]->block_size);
    char *tmp = hafs_get_file_data(slot, inode, block_start, round(node->file_size, ss[slot]->block_size) - block_start);
	memcpy(res, tmp, pos - block_start * ss[slot]->block_size);
    memcpy(res + pos - block_start * ss[slot]->block_size, buf, size);
    memcpy(res + pos - block_start * ss[slot]->block_size + size, tmp + pos - block_start * ss[slot]->block_size, round(node->file_size, ss[slot]->block_size) * ss[slot]->block_size - pos);
    
	node = hafs_get_inode(slot, inode);
    node->file_size += size;
    hafs_set_inode(slot, inode, node);
    if(hafs_put_file_data(slot, inode, block_start, round(node->file_size, ss[slot]->block_size) - block_start, res) == -1) return -1;

    return 0;
}

int hafs_rewrite_file(int slot, const char *file_name, unsigned int namelen, unsigned long long size, const char *buf)
{
    if(slot >= cnt) return -1;

    unsigned int inode = hafs_find_inode(slot, file_name, namelen, ss[slot]->root_inode);
    if(!inode) return -1;

    struct inode *node = hafs_get_inode(slot, inode);
    if(node == NULL) return -1;
    if(round(size, ss[slot]->block_size) > round(node->file_size, ss[slot]->block_size))
    {
        if(hafs_file_alloc_block(slot, inode, round(size, ss[slot]->block_size) - round(node->file_size, ss[slot]->block_size)) == -1) return -1;
    }else if(round(size, ss[slot]->block_size) < round(node->file_size, ss[slot]->block_size)){
		if(hafs_file_free_block(slot, inode, round(size, ss[slot]->block_size)) == -1) return -1;
	}
	
	node = hafs_get_inode(slot, inode);
    node->file_size = size;
    hafs_set_inode(slot, inode, node);
    
    char *buffer = (char *)malloc(round(size, ss[slot]->block_size) * ss[slot]->block_size);
    memset(buffer, 0, round(size, ss[slot]->block_size) * ss[slot]->block_size);
    memcpy(buffer, buf, size);

    if(hafs_put_file_data(slot, inode, 0, round(size, ss[slot]->block_size), buffer) == -1) return -1;

    return 0;
}

unsigned int hafs_make_dir(int slot, const char *path, unsigned int pathlen, const char *dirname, unsigned int namelen)
{
    if(slot >= cnt) return 0;
    if(namelen > 65536 || namelen == 0) return 0;

    int fa_inode;
    if(pathlen==1&&path[0]=='\\') fa_inode = ss[slot]->root_inode;
    else if((fa_inode = hafs_find_inode(slot, path, pathlen, ss[slot]->root_inode)) == 0) return 0;

    struct inode *inode = hafs_get_inode(slot, fa_inode);
    if(inode->type & INODE_DIR == 0) return 0;
    if(inode->file_size)
    {
        char *dir_entry = (char *)malloc(round(inode->file_size+4+4+namelen, ss[slot]->block_size) * ss[slot]->block_size);
        memset(dir_entry, 0, round(inode->file_size+4+4+namelen, ss[slot]->block_size) * ss[slot]->block_size);
		char *dir = hafs_get_file_data(slot, fa_inode, 0, round(inode->file_size,ss[slot]->block_size));
        memcpy(dir_entry, dir, inode->file_size);
        char *point_now = dir_entry;
        unsigned int *next_record = (unsigned int *)point_now;
        while(*next_record != 0)
        {
            char *fname = point_now + 8;
            unsigned int len = *next_record - 8;
            if(len == namelen)
            {
                if(!memcmp(fname, dirname, len))
                {
                    return 0;
                }
            }
            point_now += *next_record;
            next_record = (unsigned int *)point_now;
        }
        char *fname = point_now + 8;
        unsigned int len = inode->file_size-((char *)next_record-dir_entry) - 8;
        if(len == namelen)
        {
            if(!memcmp(fname, dirname, len))
            {
                return 0;
            }
        }
        
        if(round(inode->file_size+4+4+namelen, ss[slot]->block_size) > round(inode->file_size, ss[slot]->block_size))
        {
            if(hafs_file_alloc_block(slot, fa_inode, round(inode->file_size+4+4+namelen, ss[slot]->block_size) - round(inode->file_size, ss[slot]->block_size))) return 0;
        }

        unsigned int new_inode = hafs_alloc_inode(slot);
        if(!new_inode) return 0;
        *next_record = inode->file_size-((char *)next_record-dir_entry);
        point_now = dir_entry+inode->file_size;
        *(unsigned int *)(point_now) = 0;
        *(unsigned int *)(point_now + 4) = new_inode;
        memcpy(point_now + 8, dirname, namelen);

        hafs_put_file_data(slot, fa_inode, 0, round(inode->file_size+4+4+namelen, ss[slot]->block_size), dir_entry);

        struct inode node;
        memset(&node, 0, sizeof(node));
        node.type = INODE_PRESENT | INODE_DIR;
        hafs_set_inode(slot, new_inode, &node);

        inode = hafs_get_inode(slot, fa_inode);
        inode->file_size += 4+4+namelen;
        hafs_set_inode(slot, fa_inode, inode);

        return new_inode;
    }else{
        if(hafs_file_alloc_block(slot, fa_inode, round(4+4+namelen, ss[slot]->block_size))) return 0;
        char *dir_entry = (char *)malloc(round(4+4+namelen, ss[slot]->block_size) * ss[slot]->block_size);
        memset(dir_entry, 0, round(4+4+namelen, ss[slot]->block_size) * ss[slot]->block_size);
        unsigned int new_inode = hafs_alloc_inode(slot);
        if(!new_inode) return 0;
        *((unsigned int *)dir_entry) = 0;
        *((unsigned int *)(dir_entry + 4)) = new_inode;
        memcpy(dir_entry + 8, dirname, namelen);
        
        inode = hafs_get_inode(slot, fa_inode);
        inode->file_size = 4+4+namelen;
        hafs_set_inode(slot, fa_inode, inode);

        hafs_put_file_data(slot, fa_inode, 0, round(4+4+namelen, ss[slot]->block_size), dir_entry);

        struct inode node;
        memset(&node, 0, sizeof(node));
        node.type = INODE_PRESENT | INODE_DIR;
        hafs_set_inode(slot, new_inode, &node);

        return new_inode;
    }
    return 0;
}

int hafs_delete_file(int slot, const char *filename, int namelen)
{
	if(slot>=cnt) return -1;
	
	if(filename[namelen-1]=='\\') namelen--;
	int len = namelen;
	while(filename[len-1]!='\\') len--;
    namelen -= len;
	
	unsigned int fa_inode;
	fa_inode = hafs_find_inode(slot, filename, len, ss[slot]->root_inode);
	if(fa_inode == 0 && !(len==1 && filename[0]=='\\')) return -1;
	
	struct inode *inode = hafs_get_inode(slot, fa_inode);
    if(inode->type & INODE_DIR == 0) return -1;
    if(inode->file_size == 0) return -1;
	
	unsigned n_inode=0;
	char *dir = hafs_get_file_data(slot, fa_inode, 0, round(inode->file_size, ss[slot]->block_size));
    char *point_now = dir;
    unsigned int *next_record = (unsigned int *)point_now;
    unsigned int *last_record = (unsigned int *)point_now;
    unsigned int record_len = 0;
    while(*next_record != 0)
    {
        char *fname = point_now + 8;
        unsigned int _len = *next_record - 8;
        if(_len == namelen)
        {
            if(!memcmp(fname, filename + len, _len))
            {
            	n_inode = *(unsigned int *)(point_now + 4);
            	record_len = len + 8;
                break;
            }
        }
        last_record = (unsigned int *)point_now;
        point_now += *next_record;
        next_record = (unsigned int *)point_now;
    }
    char *fname = point_now + 8;
    unsigned int _len = inode->file_size - (point_now - dir) - 8;
    if(_len == namelen)
    {
        if(!memcmp(fname, filename + len, _len))
        {
            n_inode = *(unsigned int *)(point_now + 4);
            record_len = _len + 8;
        }
    }
    if(!n_inode) return -1;
    unsigned int block_number = round(inode->file_size,ss[slot]->block_size);
	if(*next_record)
	{
		char *tmem = (char *)malloc(inode->file_size - *next_record - ((char *)next_record - dir));
		memcpy(tmem, ((char *)next_record) + *next_record, inode->file_size - *next_record - ((char *)next_record - dir));
		memcpy(next_record, tmem, inode->file_size - *next_record - ((char *)next_record - dir));
	}else{
		*last_record = 0;
	}
	if(block_number - round(inode->file_size - record_len,ss[slot]->block_size)) hafs_file_free_block(slot, fa_inode, round(inode->file_size - record_len, ss[slot]->block_size));
	inode = hafs_get_inode(slot, fa_inode);
	inode->file_size -= record_len;
	hafs_set_inode(slot, fa_inode, inode);
	if(inode->file_size)
	{
		char *pmem = (char *)malloc(round(inode->file_size,ss[slot]->block_size));
		memset(pmem, 0, round(inode->file_size,ss[slot]->block_size));
		memcpy(pmem, dir, inode->file_size);
		hafs_put_file_data(slot, fa_inode, 0, round(inode->file_size, ss[slot]->block_size), dir);
	}
	hafs_file_free_block(slot, n_inode, 0);
	inode = hafs_get_inode(slot, n_inode);
	if(inode->type & INODE_ADDITIONAL) hafs_free_block(slot, inode->additional_block);
	memset(inode, 0, sizeof(struct inode));
	hafs_set_inode(slot, n_inode, inode);
	hafs_free_inode(slot, n_inode);
	return 0;
}

unsigned long long hafs_get_file_size(int slot, const char *filename, unsigned int namelen)
{
	if(slot>=cnt) return 0;
	unsigned int inode = hafs_find_inode(slot, filename, namelen, ss[slot]->root_inode);
	if(inode == 0 && !(namelen==1 && filename[0]=='\\')) return 0;
	struct inode *node = hafs_get_inode(slot, inode);
	if(node == NULL) return 0;
    
	return node->file_size;
}

struct dir_entry *hafs_dir_list(int slot, const char *dirname, unsigned int namelen, unsigned int *entry_number)
{
    if(slot>=cnt) return NULL;
    if(entry_number == NULL) return NULL;
    unsigned int inode = hafs_find_inode(slot, dirname, namelen, ss[slot]->root_inode);
	if(inode == 0 && !(namelen==1 && dirname[0]=='\\')) return NULL;
    struct inode *node = hafs_get_inode(slot, inode);
	if(node == NULL) return NULL;
    if(node->type & INODE_DIR == 0) return NULL;
    
    *entry_number = 0;
    if(node->file_size == 0) return NULL;
    *entry_number = 1;
    char *dir = hafs_get_file_data(slot, inode, 0, round(node->file_size, ss[slot]->block_size));
    char *point_now = dir;
    unsigned int *next_record = (unsigned int *)point_now;
    while(*next_record != 0)
    {
        (*entry_number)++;
        point_now += *next_record;
        next_record = (unsigned int *)point_now;
    }

    struct dir_entry *res = (struct dir_entry *)malloc(sizeof(struct dir_entry) * (*entry_number));
    int index = 0;
    
    point_now = dir;
    next_record = (unsigned int *)point_now;
    while(*next_record != 0)
    {
        char *fname = point_now + 8;
        unsigned int len = *next_record - 8;
        res[index].name = (char *)malloc(len+1);
        res[index].next_record = *next_record;
        res[index].inode = *(unsigned int *)(point_now + 4);
        memcpy(res[index].name, fname, len);
        res[index].name[len]=0;
        point_now += *next_record;
        next_record = (unsigned int *)point_now;
        index++;
    }
    char *fname = point_now + 8;
    unsigned int len = node->file_size - (point_now - dir) - 8;
    res[index].name = (char *)malloc(len+1);
    res[index].next_record = *next_record;
    res[index].inode = *(unsigned int *)(point_now + 4);
    res[index].name[len]=0;
    memcpy(res[index].name, fname, len);

    return res;
}

unsigned int hafs_get_file_attribute(int slot, const char *filename, unsigned int namelen)
{
	if(slot>=cnt) return 0;
	unsigned int inode = hafs_find_inode(slot, filename, namelen, ss[slot]->root_inode);
	if(inode == 0 && !(namelen==1 && filename[0]=='\\')) return 0;
	struct inode *node = hafs_get_inode(slot, inode);
	if(node == NULL) return 0;
    
	return node->type;
}

unsigned long long hafs_get_file_size_by_inode(int slot, unsigned int inode)
{
	if(slot>=cnt) return 0;
	struct inode *node = hafs_get_inode(slot, inode);
	if(node == NULL) return 0;
    
	return node->file_size;
}

unsigned int hafs_get_file_attribute_by_inode(int slot, unsigned int inode)
{
	if(slot>=cnt) return 0;
	struct inode *node = hafs_get_inode(slot, inode);
	if(node == NULL) return 0;
    
	return node->type;
}

int hafs_file_exist(int slot, const char *filename, unsigned int namelen)
{
	if(slot >= cnt) return 0;
	if(namelen == 1 && filename[0]=='\\') return 1;
	return hafs_find_inode(slot, filename, namelen, ss[slot]->root_inode) != 0;
}