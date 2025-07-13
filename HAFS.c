/* SPDX-License-Identifier: MIT */

#include <HAFS.h>

char *read_disk(int storage, unsigned long long start, unsigned int sector);
int write_disk(int storage, unsigned long long start, int sector, char *buf);
unsigned get_disk_type(int storage);

int bit_map_find(char *bitmap, unsigned int size)
{
    int i,k;
    for(i=0;i<round(size,8);i++)
    {
        if(bitmap[i]!=0xff) break;
    }
    if(bitmap[i]==0xff) return -1;
    for(k=0;k<8;k++)
    {
        if(!(bitmap[i]&(1<<k))) break;
    }
    if(i*8+k>=size) return -1;
    return i*8+k;
}

void bit_map_set(char *bitmap, unsigned int bit)
{
    bitmap[bit>>3]|=1<<(bit&0xffff);
    return;
}

void bit_map_unset(char *bitmap, unsigned int bit)
{
    bitmap[bit>>3]&=~(1<<(bit&0xffff));
    return;
}

int bit_map_get(char *bitmap, unsigned int bit)
{
    return bitmap[bit>>3]&(1<<(bit&0xffff));
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

    ss[cnt] = (struct super_sector *)read_disk(storage, 1, 1);
    if(ss[cnt]->identifier[0]!='H'||ss[cnt]->identifier[1]!='A'||ss[cnt]->identifier[2]!='F'||ss[cnt]->identifier[3]!='S')
    {
        return -1;
    }

    unsigned int sum=0;
    for(int i=0;i<sizeof(struct super_sector);i++)
    {
        sum += *((unsigned int *)ss[cnt]+i);
    }
    if(sum!=0)
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

    char buf[512];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, &_mbr, sizeof(_mbr));

    write_disk(storage, 0, 1, buf);

    struct super_sector _ss;
    memset(&_ss, 0, sizeof(_ss));

    unsigned int seg_number = size / block_size / SEG_BLOCK;

    _ss.identifier[0]='H',_ss.identifier[1]='A',_ss.identifier[2]='F',_ss.identifier[3]='S';
    _ss.size = size;
    _ss.block_size = block_size;
    _ss.block_map_start = 2;
    if(seg_number % (8 * 512))
        _ss.block_map_size = seg_number / 8 / 512 + 1;
    else
        _ss.block_map_size = seg_number / 8 / 512;
    _ss.inode_map_start = 2 + _ss.block_map_size;
    _ss.inode_map_size = _ss.block_map_size;
    if((_ss.inode_map_start + _ss.inode_map_size) % block_size)
        _ss.zero_seg_start = (_ss.inode_map_start + _ss.inode_map_size) / block_size + 1;
    else
        _ss.zero_seg_start = (_ss.inode_map_start + _ss.inode_map_size) / block_size;
    _ss.root_inode = 0;
    _ss.type = FS_TYPE_HD;
    _ss.inode_per_seg = inode_number;
    _ss.seg_number = seg_number;

    unsigned int sum=0;
    for(int i=0;i<sizeof(struct super_sector);i++)
    {
        sum += *((unsigned int *)&_ss+i);
    }
    _ss.crc = ~sum;

    memset(buf, 0, sizeof(buf));
    memcpy(buf, &_ss, sizeof(_ss));

    write_disk(storage, 1, 1, buf);

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
    sss.block_left = sss.block_number - sss.inode_rel_start - inode_number / (block_size / sizeof(struct inode)) - _ss.zero_seg_start;
    sss.inode_left = inode_number;

    unsigned int sum=0;
    for(int k=0;k<sizeof(struct seg_super_sector);k++)
    {
        sum += *((unsigned int *)&sss+k);
    }
    sss.crc = ~sum;

    memset(buf, 0, sizeof(buf));
    memcpy(buf, &sss, sizeof(sss));

    write_disk(storage, _ss.zero_seg_start * block_size, 1, buf);

    memset(buf, 0, sizeof(buf));
    for(int k=0;k<sss.inode_rel_start + inode_number / (block_size / sizeof(struct inode));k++)
    {
        bit_map_set(buf,k);
    }
    write_disk(storage, sss.block_map_rel_start, 1, buf);

    memset(buf, 0, sizeof(buf));
    bit_map_set(buf,0);
    write_disk(storage, sss.inode_map_rel_start, 1, buf);
    
    struct inode root;
    memset(root, 0, sizeof(root));
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
        sss.block_left = sss.block_number - sss.inode_rel_start - inode_number / (block_size / sizeof(struct inode));
        sss.inode_left = inode_number;

        unsigned int sum=0;
        for(int k=0;k<sizeof(struct seg_super_sector);k++)
        {
            sum += *((unsigned int *)&sss+k);
        }
        sss.crc = ~sum;

        memset(buf, 0, sizeof(buf));
        memcpy(buf, &sss, sizeof(sss));

        write_disk(storage, 1LL * i * SEG_BLOCK * block_size, 1, buf);

        memset(buf, 0, sizeof(buf));
        for(int k=0;k<sss.inode_rel_start + inode_number / (block_size / sizeof(struct inode));k++)
        {
            bit_map_set(buf,k);
        }
        write_disk(storage, 1LL * i * SEG_BLOCK * block_size + 1, 1, buf);
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
        sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start, 1);
        seg_start = 0;
    }else{
        sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * inode_seg, 1);
        seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * inode_seg;
    }

    struct inode *node = (struct inode *)(read_disk(slot_storage[slot], seg_start + sss->inode_rel_start + inode_in_seg_sector, 1) + inode_in_sector * sizeof(struct inode));
    if(node->type & INODE_PRESENT == 0) return NULL;
    return node;
}

int hafs_set_inode(int slot, unsigned int inode, struct inode *node)
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
        sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start, 1);
        seg_start = 0;
    }else{
        sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * inode_seg, 1);
        seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * inode_seg;
    }

    char *point = read_disk(slot_storage[slot], seg_start + sss->inode_rel_start + inode_in_seg_sector, 1);
    memcpy(point + inode_in_sector * sizeof(struct inode), node, sizeof(struct inode));
    write_disk(slot_storage[slot], seg_start + sss->inode_rel_start + inode_in_seg_sector, 1, point);
    
    return node;
}

char *hafs_get_block(int slot, unsigned int block_number)
{
    if(slot >= cnt) return NULL;
    return read_disk(slot_storage[slot], 1LL * block_number * ss[slot]->block_size / 0x200, ss[slot]->block_size / 0x200);
}

int hafs_put_block(int slot, unsigned int block_number, char *buf)
{
    if(slot >= cnt) return NULL;
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
    char *block = (char *)malloc(block_number * ss[slot]->block_size);
    int block_index = 0;
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

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int i=0;i<8;i++)
        {
            ind1 = (unsigned int *)hafs_get_block(slot, node->indirect_1[i]);
            for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
            {
                if(12 + i*k < start_block) continue;
                chunk = hafs_get_block(slot, ind1[k]);
                memcpy((block + block_index * ss[slot]->block_size), chunk, ss[slot]->block_size);
                block_index++;
                if(block_index == block_number) return block;
            }
        }
    }

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
                    if(12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + m*i*k < start_block) continue;
                    chunk = hafs_get_block(slot, ind1[k]);
                    memcpy((block + block_index * ss[slot]->block_size), chunk, ss[slot]->block_size);
                    block_index++;
                    if(block_index == block_number) return block;
                }
            }
        }
    }

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
                        if(12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int) + n*m*i*k < start_block) continue;
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

int hafs_put_file_data(int slot, unsigned int inode, unsigned int start_block, unsigned int block_number, char *buf)
{
    if(slot >= cnt) return -1;
    struct inode *node = hafs_get_inode(slot, inode);
    if(start_block + block_number > round(node->file_size,ss[slot]->block_size))
    {
        return -1;
    }
    int block_index = 0;
    if(start_block < 12)
    {
        char *chunk;
        for(int i=start_block;i<12;i++)
        {
            chunk = buf + block_index * ss[slot]->block_size;
            hafs_put_block(slot, node->direct[i], buf);
            block_index++;
            if(block_index == block_number) return 0;
        }
    }
    
    char *chunk;
    unsigned int *ind1,*ind2,*ind3;

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int i=0;i<8;i++)
        {
            ind1 = (unsigned int *)hafs_get_block(slot, node->indirect_1[i]);
            for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
            {
                if(12 + i*k < start_block) continue;
                chunk = buf + block_index * ss[slot]->block_size;
                hafs_put_block(slot, ind1[k], chunk);
                block_index++;
                if(block_index == block_number) return 0;
            }
        }
    }

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
                    if(12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + m*i*k < start_block) continue;
                    chunk = buf + block_index * ss[slot]->block_size;
                    hafs_put_block(slot, ind1[k], chunk);
                    block_index++;
                    if(block_index == block_number) return 0;
                }
            }
        }
    }

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
                        if(12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int) + n*m*i*k < start_block) continue;
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

unsigned int hafs_find_inode(int slot, char *pathname, unsigned int len, unsigned int u_inode)      //pathname must be \xxxx\xxxx\xxxx\xxx.xxx
{
    if(slot >= cnt) return 0;
    if(len < 1) return 0;
    if(pathname[0] != '\\') return 0;
    int i;
    for(i=1;i<len;i++)
    {
        if(pathname[i] == '\\') break;
    }
    if(i==len-1)
    {
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
                if(memcpy(filename, pathname+1, len))
                {
                    return *(next_record+4);
                }
            }
            point_now += *next_record;
            *next_record = (unsigned int *)point_now;
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
                if(memcpy(filename, pathname+1, _len))
                {
                    return hafs_find_inode(slot, pathname + 1 + len, len-_len-1, *(next_record+4));
                }
            }
            point_now += *next_record;
            *next_record = (unsigned int *)point_now;
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
        sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start, 1);
        seg_start = 0;
    }else{
        sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * seg, 1);
        seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * seg;
    }
    
    char *seg_block_bitmap = read_disk(slot_storage[slot], seg_start + sss->block_map_rel_start, 1);

    int block;
    if((block = bit_map_find(seg_block_bitmap, SEG_BLOCK)) == -1) return 0;

    bit_map_set(seg_block_bitmap,block);
    sss->block_left--;
    write_disk(slot_storage[slot], seg_start + sss->block_map_rel_start, 1, seg_block_bitmap);
    if(seg == 0)
    {
        write_disk(slot_storage[slot], ss[slot]->zero_seg_start, 1, sss);
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
    
    int t,num=0;
    while(((t = bit_map_find(block_bitmap, ss[slot]->seg_number)) != -1))
    {
        struct seg_super_sector *sss;
        unsigned long long seg_start = 0;
        if(t == 0)
        {
            sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start, 1);
            seg_start = 0;
        }else{
            sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * t, 1);
            seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * t;
        }
        num+=sss->block_left;
        if(num>=block_number) break;
    }

    if(num<block_number) return NULL;

    unsigned int *blocks = (unsigned int *)malloc(block_number);
    int point = 0;
    while(block_number)
    {
        int seg;
        if((seg = bit_map_find(block_bitmap, ss[slot]->seg_number)) == -1) return NULL;
        
        struct seg_super_sector *sss;
        unsigned long long seg_start = 0;
        if(seg == 0)
        {
            sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start, 1);
            seg_start = 0;
        }else{
            sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * seg, 1);
            seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * seg;
        }
        
        char *seg_block_bitmap = read_disk(slot_storage[slot], seg_start + sss->block_map_rel_start, 1);
        
        while(block_number && sss->block_left)
        {
            int block;
            if((block = bit_map_find(seg_block_bitmap, SEG_BLOCK)) == -1) break;
            
            bit_map_set(seg_block_bitmap,block);
            sss->block_left--;
            blocks[point++] = seg * SEG_BLOCK + block;
            block_number--;
        }

        write_disk(slot_storage[slot], seg_start + sss->block_map_rel_start, 1, seg_block_bitmap);
        if(seg == 0)
        {
            write_disk(slot_storage[slot], ss[slot]->zero_seg_start, 1, sss);
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
        sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start, 1);
        seg_start = 0;
    }else{
        sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * seg, 1);
        seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * seg;
    }
    
    char *seg_inode_bitmap = read_disk(slot_storage[slot], seg_start + sss->inode_map_rel_start, sss->inode_rel_start - sss->inode_map_rel_start);

    int inode;
    if((inode = bit_map_find(seg_inode_bitmap, ss[slot]->inode_per_seg)) == -1) return 0;

    bit_map_set(seg_inode_bitmap,inode);
    sss->inode_left--;
    write_disk(slot_storage[slot], seg_start + sss->inode_map_rel_start, 1, seg_inode_bitmap);
    if(seg == 0)
    {
        write_disk(slot_storage[slot], ss[slot]->zero_seg_start, 1, sss);
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
        sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start, 1);
        seg_start = 0;
    }else{
        sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * t, 1);
        seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * t;
    }

    unsigned int block_in_seg = block_number % SEG_BLOCK;
    if(block_in_seg < sss->inode_rel_start + ss[slot]->inode_per_seg / (ss[slot]->block_size / sizeof(struct inode))) return -1;

    char *seg_block_bitmap = read_disk(slot_storage[slot], seg_start + sss->block_map_rel_start, 1);
    
    if(!bit_map_get(seg_block_bitmap, block_in_seg)) return -1;

    bit_map_unset(seg_block_bitmap, block_in_seg);
    sss->block_left++;
    write_disk(slot_storage[slot], seg_start + sss->block_map_rel_start, 1, seg_block_bitmap);
    if(t == 0)
    {
        write_disk(slot_storage[slot], ss[slot]->zero_seg_start, 1, sss);
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
        sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start, 1);
        seg_start = 0;
    }else{
        sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * t, 1);
        seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * t;
    }

    unsigned int inode_in_seg = inode_number % ss[slot]->inode_per_seg;

    char *seg_inode_bitmap = read_disk(slot_storage[slot], seg_start + sss->inode_map_rel_start, 1);
    
    if(!bit_map_get(seg_inode_bitmap, inode_in_seg)) return -1;

    bit_map_unset(seg_inode_bitmap, inode_in_seg);
    sss->inode_left++;
    write_disk(slot_storage[slot], seg_start + sss->inode_map_rel_start, 1, seg_inode_bitmap);
    if(t == 0)
    {
        write_disk(slot_storage[slot], ss[slot]->zero_seg_start, 1, sss);
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
    
    int t, num=0, tot =  _calc_block_number(ss[slot]->block_size, round(node->file_size, ss[slot]->block_size) + add_number) - _calc_block_number(ss[slot]->block_size, add_number);
    while(((t = bit_map_find(block_bitmap, ss[slot]->seg_number)) != -1))
    {
        struct seg_super_sector *sss;
        unsigned long long seg_start = 0;
        if(t == 0)
        {
            sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->zero_seg_start, 1);
            seg_start = 0;
        }else{
            sss = (struct sss *)read_disk(slot_storage[slot], ss[slot]->block_size / 0x200 * SEG_BLOCK * t, 1);
            seg_start = ss[slot]->block_size / 0x200 * SEG_BLOCK * t;
        }
        num+=sss->block_left;
        if(num>=tot) break;
    }

    if(num<tot) return 0;

    unsigned int *blocks = hafs_alloc_blocks(slot, add_number);
    if(blocks == NULL) return -1;

    int start_block = round(node->file_size, ss[slot]->block_size);
    int block_index = 0;
    if(start_block < 12)
    {
        for(int i=start_block;i<12;i++)
        {
            node->direct[i] = blocks[block_index];
            if(block_index == add_number)
            {
                hafs_set_inode(slot, inode, node);
                return 0;
            }
        }
    }
    
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
                ind1 = malloc(ss[slot]->block_size);
            }else ind1 = (unsigned int *)hafs_get_block(slot, node->indirect_1[i]);
            for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
            {
                if(12 + i*k < start_block) continue;
                ind1[k] = blocks[block_index];
                block_index++;
                if(block_index == add_number)
                {
                    hafs_put_block(slot, node->indirect_1[i], ind1);
                    hafs_set_inode(slot, inode, node);
                    return 0;
                }
            }
            hafs_put_block(slot, node->indirect_1[i], ind1);
        }
    }

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int m=0;m<4;m++)
        {
            if(!node->indirect_2[m])
            {
                node->indirect_2[m] = hafs_alloc_block(slot);
                if(!node->indirect_2[m]) return -1;
                ind2 = malloc(ss[slot]->block_size);
            }else ind2 = (unsigned int *)hafs_get_block(slot, node->indirect_2[m]);
            for(int i=0;i<ss[slot]->block_size / sizeof(unsigned int);i++)
            {
                if(!ind2[i])
                {
                    ind2[i] = hafs_alloc_block(slot);
                    if(!ind2[i]) return -1;
                    ind1 = malloc(ss[slot]->block_size);
                }else ind1 = (unsigned int *)hafs_get_block(slot, ind2[i]);
                for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
                {
                    if(12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + m*i*k < start_block) continue;
                    ind1[k] = blocks[block_index];
                    block_index++;
                    if(block_index == add_number)
                    {
                        hafs_put_block(slot, node->indirect_2[m], ind2);
                        hafs_put_block(slot, ind2[i], ind1);
                        hafs_set_inode(slot, inode, node);
                        return 0;
                    }
                }
                hafs_put_block(slot, ind2[i], ind1);
            }
            hafs_put_block(slot, node->indirect_2[m], ind2);
        }
    }

    if(start_block < 12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int))
    {
        for(int n=0;n<4;n++)
        {
            if(!node->indirect_3[n])
            {
                node->indirect_3[n] = hafs_alloc_block(slot);
                if(!node->indirect_3[n]) return -1;
                ind3 = malloc(ss[slot]->block_size);
            }else ind3 = (unsigned int *)hafs_get_block(slot, node->indirect_3[n]);
            for(int m=0;m<ss[slot]->block_size / sizeof(unsigned int);m++)
            {
                if(!ind3[m])
                {
                    ind3[m] = hafs_alloc_block(slot);
                    if(!ind3[m]) return -1;
                    ind2 = malloc(ss[slot]->block_size);
                }else ind2 = (unsigned int *)hafs_get_block(slot, ind3[m]);
                for(int i=0;i<ss[slot]->block_size / sizeof(unsigned int);i++)
                {
                    if(!ind2[i])
                    {
                        ind2[i] = hafs_alloc_block(slot);
                        if(!ind2[i]) return -1;
                        ind1 = malloc(ss[slot]->block_size);
                    }else ind1 = (unsigned int *)hafs_get_block(slot, ind2[i]);
                    for(int k=0;k<ss[slot]->block_size / sizeof(unsigned int);k++)
                    {
                        if(12 + 8 * ss[slot]->block_size / sizeof(unsigned int) + 4 * ss[slot]->block_size / sizeof(unsigned int) * ss[slot]->block_size / sizeof(unsigned int) + n*m*i*k < start_block) continue;
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

unsigned int hafs_create_file(int slot, char *path, unsigned int pathlen, char *filename, unsigned int namelen)
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
        char *dir_entry = malloc(round(inode->file_size+4+4+namelen, ss[slot]->block_size) * ss[slot]->block_size);
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
                if(memcpy(fname, filename, len))
                {
                    return 0;
                }
            }
            point_now += *next_record;
            *next_record = (unsigned int *)point_now;
        }

        if(round(inode->file_size+4+4+namelen, ss[slot]->block_size) > round(inode->file_size, ss[slot]->block_size))
        {
            if(hafs_file_alloc_block(slot, fa_inode, round(inode->file_size+4+4+namelen, ss[slot]->block_size) - round(inode->file_size, ss[slot]->block_size))) return 0;
        }

        unsigned int new_inode = hafs_alloc_inode(slot);
        if(!new_inode) return 0;
        *next_record = inode->file_size;
        point_now = inode->file_size;
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
        char *dir_entry = malloc(round(4+4+namelen, ss[slot]->block_size) * ss[slot]->block_size);
        unsigned int new_inode = hafs_alloc_inode(slot);
        if(!new_inode) return 0;
        *(unsigned int *)dir_entry = 0;
        *(unsigned int *)(dir_entry + 4) = 0;
        memcpy(dir_entry + 8, filename, namelen);

        hafs_put_file_data(slot, fa_inode, 0, round(4+4+namelen, ss[slot]->block_size), dir_entry);

        struct inode node;
        memset(&node, 0, sizeof(node));
        node.type = INODE_PRESENT | INODE_FILE;
        hafs_set_inode(slot, new_inode, &node);

        inode = hafs_get_inode(slot, fa_inode);
        inode->file_size = 4+4+namelen;
        hafs_set_inode(slot, fa_inode, inode);

        return new_inode;
    }
    return 0;
}

char *hafs_read_file(int slot, char *file_name, unsigned int namelen, unsigned long long pos, unsigned long long size)
{
    if(slot >= cnt) return NULL;

    unsigned int inode = hafs_find_inode(slot, file_name, namelen, ss[slot]->root_inode);
    if(!inode) return NULL;

    struct inode *node = hafs_get_inode(slot, inode);
    if(node == NULL) return NULL;
    if(pos + size >= node->file_size) return NULL;

    unsigned int block_start = pos / ss[slot]->block_size, block_number = round(pos + size, ss[slot]->block_size);
    char *tmp = hafs_get_file_data(slot, inode, block_start, block_number);
    char *res = malloc(size);
    memcpy(res, tmp + pos - block_start * ss[slot]->block_size, size);
    return res;
}

int hafs_write_file(int slot, char *file_name, unsigned int namelen, unsigned long long pos, unsigned long long size, char *buf)
{
    if(slot >= cnt) return -1;

    unsigned int inode = hafs_find_inode(slot, file_name, namelen, ss[slot]->root_inode);
    if(!inode) return -1;

    struct inode *node = hafs_get_inode(slot, inode);
    if(node == NULL) return -1;
    if(round(node->file_size, ss[slot]->block_size + size) - round(node->file_size, ss[slot]->block_size))
    {
        if(hafs_file_alloc_block(slot, inode, round(node->file_size, ss[slot]->block_size + size) - round(node->file_size, ss[slot]->block_size)) == -1) return -1;
    }

    unsigned int block_start = pos / ss[slot]->block_size, block_number = round(pos + size, ss[slot]->block_size);
    char *res = malloc(block_number * ss[slot]->block_size);
    char *tmp = hafs_get_file_data(slot, inode, block_start, round(node->file_size, ss[slot]->block_size) - block_start);
    memcpy(res, tmp, pos - block_start * ss[slot]->block_size);
    memcpy(res + pos - block_start * ss[slot]->block_size, buf , size);
    memcpy(res + pos - block_start * ss[slot]->block_size + size, tmp + pos - block_start * ss[slot]->block_size, round(node->file_size, ss[slot]->block_size) * ss[slot]->block_size - pos);
    
    if(hafs_put_file_data(slot, inode, block_start, block_number, res) == -1) return -1;

    return 0;
}

unsigned int hafs_make_dir(int slot, char *path, unsigned int pathlen, char *dirname, unsigned int namelen)
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
        char *dir_entry = malloc(round(inode->file_size+4+4+namelen, ss[slot]->block_size) * ss[slot]->block_size);
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
                if(memcpy(fname, dirname, len))
                {
                    return 0;
                }
            }
            point_now += *next_record;
            *next_record = (unsigned int *)point_now;
        }

        if(round(inode->file_size+4+4+namelen, ss[slot]->block_size) > round(inode->file_size, ss[slot]->block_size))
        {
            if(hafs_file_alloc_block(slot, fa_inode, round(inode->file_size+4+4+namelen, ss[slot]->block_size) - round(inode->file_size, ss[slot]->block_size))) return 0;
        }

        unsigned int new_inode = hafs_alloc_inode(slot);
        if(!new_inode) return 0;
        *next_record = inode->file_size;
        point_now = inode->file_size;
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
        char *dir_entry = malloc(round(4+4+namelen, ss[slot]->block_size) * ss[slot]->block_size);
        unsigned int new_inode = hafs_alloc_inode(slot);
        if(!new_inode) return 0;
        *(unsigned int *)dir_entry = 0;
        *(unsigned int *)(dir_entry + 4) = 0;
        memcpy(dir_entry + 8, dirname, namelen);

        hafs_put_file_data(slot, fa_inode, 0, round(4+4+namelen, ss[slot]->block_size), dir_entry);

        struct inode node;
        memset(&node, 0, sizeof(node));
        node.type = INODE_PRESENT | INODE_DIR;
        hafs_set_inode(slot, new_inode, &node);

        inode = hafs_get_inode(slot, fa_inode);
        inode->file_size = 4+4+namelen;
        hafs_set_inode(slot, fa_inode, inode);

        return new_inode;
    }
    return 0;
}