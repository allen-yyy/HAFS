/* SPDX-License-Identifier: MIT */

#include <bits/stdc++.h>
#include "HAFS.h"
#include <windows.h>
#include <winioctl.h>
using namespace std;

HANDLE hDevices[26];
map<char,int> letter2storage;
static int cnt;

char *read_disk(int storage, unsigned long long start, unsigned int sector)
{
	OVERLAPPED over = { 0 };
	start *= 512;
	over.Offset = start & 0xFFFFFFFF;
    over.OffsetHigh = (start >> 32) & 0xFFFFFFFF;
	char* buffer = new char[sector * 512 + 1];
	DWORD readsize;
	if (ReadFile(hDevices[storage], buffer, sector * 512, &readsize, &over) == 0)
	{
		return NULL;
	}
	return buffer;
}
int write_disk(int storage, unsigned long long start, int sector, const void *buf)
{
    OVERLAPPED over = { 0 };
    start *= 512;
	over.Offset = start & 0xFFFFFFFF;
    over.OffsetHigh = (start >> 32) & 0xFFFFFFFF;
	DWORD writesize;
    char *buffer = (char *)malloc(sector * 512);
    memcpy(buffer, buf, sector * 512);
	if (WriteFile(hDevices[storage], buffer, sector * 512, &writesize, &over) == 0)
	{
        printf("\n%d\n",GetLastError());
		return -1;
	}
	return 0;
}
unsigned int get_disk_type(int storage)
{
    return 0xF8;
}

int is_NTFS(string rootPath) {
    char fileSystemName[MAX_PATH + 1];
    DWORD serialNumber = 0;
    DWORD maxComponentLen = 0;
    DWORD fileSystemFlags = 0;
    if (GetVolumeInformationA(rootPath.c_str(), NULL, 0, &serialNumber, &maxComponentLen, &fileSystemFlags, fileSystemName, sizeof(fileSystemName)))
	{
        return (_stricmp(fileSystemName, "NTFS") == 0);
    }
    return 0;
}

int open_disk(const char *disk)
{
	HANDLE handle = CreateFileA(disk, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if(handle == INVALID_HANDLE_VALUE) return -1;
	hDevices[cnt] = handle;
	return cnt++;
}
long long get_disk_size(const char* szPath)
{
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    BOOL bResult = FALSE;
    DWORD junk = 0;
 
    hDevice = CreateFileA(szPath,
                        GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_EXISTING,
                        0,
                        NULL);
    if (hDevice == INVALID_HANDLE_VALUE) return FALSE;
    
	GET_LENGTH_INFORMATION lengthInfo;
    DWORD bytesReturned = 0;
    bResult = DeviceIoControl(
        hDevice,
        IOCTL_DISK_GET_LENGTH_INFO,
        NULL,
        0,
        &lengthInfo,
        sizeof(lengthInfo),
        &bytesReturned,
        NULL
    );
    CloseHandle(hDevice);
    return lengthInfo.Length.QuadPart;
}
int file_exists(string filename)
{
    DWORD attr = GetFileAttributesA(filename.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

void cmd_copy(string name1, string name2)
{
	int is_hafs1 = 0, is_hafs2 = 0;
	
	if(name1.size() > 2 && name1[1] == ':' && !is_NTFS(("\\\\.\\"+name1.substr(0, 2)).c_str()))
	{
		if(letter2storage.count(toupper(name1[0]))) is_hafs1 = 1;
		else{
			int storage = open_disk(("\\\\.\\"+name1.substr(0, 2)).c_str());
			if(storage != -1)
			{
				int slot = hafs_load_fs(storage);
				if(slot >= 0)
				{
					is_hafs1 = 1;
					letter2storage[toupper(name1[0])] = storage;
				}else{
					CloseHandle(hDevices[storage]);
				}
			}
		}
	}
	if(name2.size() > 2 && name2[1] == ':' && !is_NTFS(("\\\\.\\"+name2.substr(0, 2)).c_str()))
	{
		if(letter2storage.count(toupper(name2[0]))) is_hafs2 = 1;
		else{
			int storage = open_disk(("\\\\.\\"+name2.substr(0, 2)).c_str());
			if(storage != -1)
			{
				int slot = hafs_load_fs(storage);
				if(slot >= 0)
				{
					is_hafs2 = 1;
					letter2storage[toupper(name2[0])] = slot;
				}else{
					CloseHandle(hDevices[storage]);
				}
			}
		}
	}
	char *buffer;
	long long file_size;
	if(!is_hafs2)
	{
		if(!file_exists(name2))
		{
			cout<<"Error : Source file doesn't exist, please check file system(NTFS)."<<endl;
	        return;
		}
		FILE *file;
	    
	    file = fopen(name2.c_str(), "rb");
	    if (file == NULL) {
	        cout<<"Error : Source file opening failed."<<endl;
	        return;
	    }
	 
	    fseek(file, 0, SEEK_END);
	    file_size = ftell(file);
	    rewind(file);
	 	
	 	if(file_size)
	 	{
	 		buffer = (char *)malloc(file_size);
	    	fread(buffer, 1, file_size, file);
		}
	}else{
		if(!hafs_file_exist(letter2storage[toupper(name2[0])], name2.substr(2, name2.size()-2).c_str(), name2.size()-2))
		{
			cout<<"Error : Source file doesn't exist, please check file system."<<endl;
	        return;
		}
		
		file_size = hafs_get_file_size(letter2storage[toupper(name2[0])], name2.substr(2, name2.size()-2).c_str(), name2.size()-2);
		
		if(file_size)
		{
			buffer = (char *)malloc(file_size);
			char *tmp = hafs_read_file(letter2storage[toupper(name2[0])], name2.substr(2, name2.size()-2).c_str(), name2.size()-2, 0, file_size);
			memcpy(buffer, tmp, file_size);
		}
	}
	
	if(!is_hafs1)
	{
		if(file_exists(name1))
		{
			cout<<"Destination file already exisited, ARE YOU SURE TO OVERWRITE?[y/N]:";
			string c;
			cin>>c;
			getchar();
			if(c.size()!=1&&(c[0]!='y'&&c[0]!='Y')) return;
		}
		FILE *file;
	    
	    file = fopen(name1.c_str(), "wb");
		if (file == NULL) {
	        cout<<"Error : Destination file opening failed."<<endl;
	        return;
	    }
	    if(file_size)
	 	{
	    	fwrite(buffer, 1, file_size, file);
	    	fflush(file);
	    	fclose(file);
		}
	}else{
		if(hafs_file_exist(letter2storage[toupper(name1[0])], name1.substr(2, name1.size()-2).c_str(), name1.size()-2))
		{
			unsigned int att = hafs_get_file_attribute(letter2storage[toupper(name1[0])], name1.substr(2, name1.size()-2).c_str(), name1.size()-2);
			if(att & INODE_DIR)
			{
				cout<<"Error : Can't copy a file to a directory."<<endl;
				return;
			}
			cout<<"Destination file already exisited, ARE YOU SURE TO OVERWRITE?[y/N]:";
			string c;
			cin>>c;
			getchar();
			if(c.size()!=1&&(c[0]!='y'&&c[0]!='Y')) return;
		}else{
			int i=name1.size()-1;
			while(i>2&&name1[i]!='\\') i--;
			if(name1[i]!='\\')
			{
				cout<<"Error : Wrong destination file path."<<endl;
				return;
			}
			if(!hafs_create_file(letter2storage[toupper(name1[0])], name1.substr(2, i-1).c_str(), i-1, name1.substr(i+1, name1.size() - i - 1).c_str(), name1.size() - i - 1))
			{
				cout<<"Error : Destination file creating failed."<<endl;
				return;
			}
		}
		if(file_size)
		{
			hafs_rewrite_file(letter2storage[toupper(name1[0])], name1.substr(2, name1.size()-2).c_str(), name1.size()-2, file_size, buffer);
		}
	}
	return;
}

void cmd_mkfs(string partition, unsigned int block_size, unsigned int inode_number)
{
	int storage = open_disk(("\\\\.\\"+partition).c_str());
	if(storage == -1)
	{
		cout<<"Error : Can't open the disk."<<endl;
		return;
	}
	
	unsigned long long disk_size = get_disk_size(("\\\\.\\"+partition).c_str());
	if(block_size != 1024 && block_size != 2048 && block_size != 4096)
	{
		cout<<"Error : Parameter invalid!"<<endl;
		return;
	}
    if(inode_number % (block_size / sizeof(struct inode)))
    {
		cout<<"Error : Parameter invalid!"<<endl;
		return;
	}
    if(disk_size % block_size)
    {
		cout<<"Error : Parameter invalid!"<<endl;
		return;
	}
    if(((block_size == 1024 || block_size == 2048) && inode_number > 4096) || (block_size == 4096 && inode_number > 20480))
    {
		cout<<"Error : Parameter invalid!"<<endl;
		return;
	}
    if(disk_size < block_size * SEG_BLOCK)
    {
		cout<<"Error : The space of the partition is not enough."<<endl;
		return;
	}
    
	cout<<"Parameters:"<<endl;
	cout<<"Partition size in total : "<<disk_size<<"B"<<endl;
	cout<<"Block size : "<<block_size<<"B"<<endl;
	cout<<"Inode number per segment : "<<inode_number<<endl;
	
	cout<<"This operation will delete all your files and data, ARE YOU SURE TO CONTINUE?[y/N]:";
	string c;
	cin>>c;
	getchar();
	if(c.size()!=1&&(c[0]!='y'&&c[0]!='Y')) return;
	
	hafs_make_fs(storage, disk_size, block_size, inode_number);

	cnt--;
	return;
}

void cmd_delete(string file_name)
{
	if(file_name.size() < 2 || file_name[1] != ':' || is_NTFS(("\\\\.\\"+file_name.substr(0, 2)).c_str()))
	{
		cout<<"Error : Wrong path name!"<<endl;
		return;
	}
	if(!letter2storage.count(toupper(file_name[0])))
	{
		int storage = open_disk(("\\\\.\\"+file_name.substr(0, 2)).c_str());
		if(storage == -1)
		{
			cout<<"Error : Disk opening failed!"<<endl;
			return;
		}else{
			int slot = hafs_load_fs(storage);
			if(slot >= 0)
			{
				letter2storage[toupper(file_name[0])] = storage;
			}else{
				CloseHandle(hDevices[storage]);
				cout<<"Error : File system unknown!"<<endl;
				return;
			}
		}
	}
	unsigned int att = hafs_get_file_attribute(letter2storage[toupper(file_name[0])], file_name.substr(2, file_name.size()-2).c_str(), file_name.size()-2);
	
	if((att & INODE_PRESENT) == 0)
	{
		cout<<"Error : File doesn't exist!"<<endl;
		return;
	}
	
	if(att & INODE_DIR)
	{
		if(hafs_get_file_size(letter2storage[toupper(file_name[0])], file_name.substr(2, file_name.size()-2).c_str(), file_name.size()-2) != 0)
		{
			cout<<"Error : Can't delete a directory that is not empty."<<endl;
			return;
		}
	}
	
	hafs_delete_file(letter2storage[toupper(file_name[0])], file_name.substr(2, file_name.size()-2).c_str(), file_name.size()-2);
	return;
}

void cmd_mkdir(string file_name)
{
	if(file_name.size() < 2 || file_name[1] != ':' || is_NTFS(("\\\\.\\"+file_name.substr(0, 2)).c_str()))
	{
		cout<<"Error : Wrong path name!"<<endl;
		return;
	}
	if(!letter2storage.count(toupper(file_name[0])))
	{
		int storage = open_disk(("\\\\.\\"+file_name.substr(0, 2)).c_str());
		if(storage == -1)
		{
			cout<<"Error : Disk opening failed!"<<endl;
			return;
		}else{
			int slot = hafs_load_fs(storage);
			if(slot >= 0)
			{
				letter2storage[toupper(file_name[0])] = storage;
			}else{
				CloseHandle(hDevices[storage]);
				cout<<"Error : File system unknown!"<<endl;
				return;
			}
		}
	}
	unsigned int att = hafs_get_file_attribute(letter2storage[toupper(file_name[0])], file_name.substr(2, file_name.size()-2).c_str(), file_name.size()-2);
	
	if(att & INODE_PRESENT)
	{
		cout<<"Error : Directory already existed!"<<endl;
		return;
	}
	
	int i=file_name.size()-1;
	while(i>2&&file_name[i]!='\\') i--;
	if(file_name[i]!='\\')
	{
		cout<<"Error : Wrong path."<<endl;
		return;
	}
	if(!hafs_make_dir(letter2storage[toupper(file_name[0])], file_name.substr(2, i-1).c_str(), i-1, file_name.substr(i+1, file_name.size() - i - 1).c_str(), file_name.size() - i - 1))
	{
		cout<<"Error : Directory creating failed."<<endl;
		return;
	}
	return;
}

void cmd_dir(string file_name)
{
	if(file_name.size() < 2 || file_name[1] != ':' || is_NTFS(("\\\\.\\"+file_name.substr(0, 2)).c_str()))
	{
		cout<<"Error : Wrong path name!"<<endl;
		return;
	}
	if(!letter2storage.count(toupper(file_name[0])))
	{
		int storage = open_disk(("\\\\.\\"+file_name.substr(0, 2)).c_str());
		if(storage == -1)
		{
			cout<<"Error : Disk opening failed!"<<endl;
			return;
		}else{
			int slot = hafs_load_fs(storage);
			if(slot >= 0)
			{
				letter2storage[toupper(file_name[0])] = storage;
			}else{
				CloseHandle(hDevices[storage]);
				cout<<"Error : File system unknown!"<<endl;
				return;
			}
		}
	}
	unsigned int att = hafs_get_file_attribute(letter2storage[toupper(file_name[0])], file_name.substr(2, file_name.size()-2).c_str(), file_name.size()-2);
	
	if((att & INODE_PRESENT) == 0)
	{
		cout<<"Error : Directory doesn't exist!"<<endl;
		return;
	}
	
	if((att & INODE_DIR) == 0)
	{
		if(hafs_get_file_size(letter2storage[toupper(file_name[0])], file_name.substr(2, file_name.size()-2).c_str(), file_name.size()-2) != 0)
		{
			cout<<"Error : Not a directory."<<endl;
			return;
		}
	}
	
	unsigned int number = 0;
	struct dir_entry *list=hafs_dir_list(letter2storage[toupper(file_name[0])], file_name.substr(2, file_name.size()-2).c_str(), file_name.size()-2, &number);
	cout<<number<<" file(s) in total."<<endl;
	for(int i=0;i<number;i++)
	{
		cout<<setw(32)<<setiosflags(ios::left)<<list[i].name;
		cout<<setw(16)<<(hafs_get_file_attribute_by_inode(letter2storage[toupper(file_name[0])], list[i].inode)&INODE_FILE?hafs_get_file_size_by_inode(letter2storage[toupper(file_name[0])], list[i].inode):0);
		cout<<setiosflags(ios::left)<<setw(10)<<(hafs_get_file_attribute_by_inode(letter2storage[toupper(file_name[0])], list[i].inode)&INODE_DIR?"DIR":" ")<<endl;
	}
	return;
}

int main()
{
	cout<<"Haribote File System (Version 1.0) CLI for Windows Version 0.9"<<endl;
	cout<<"(c) Allen He 2025. Distribute under MIT license."<<endl;	
	while(1)
	{
		string cmdline;
		cout<<">";
		getline(cin, cmdline);
		if(!cmdline.size() || cmdline[0] == '\n') continue;
		
		if(cmdline.size() >= 4 && cmdline.substr(0, 4) == "copy")
		{
			if(cmdline.size() <= 5)
			{
				cout<<"Error : Too few parameters of command copy!"<<endl;
				continue;
			}
			string rest = cmdline.substr(5, cmdline.size() - 5);
			string name1 = "", name2 = "";
			int inside = 0, second_flag = 0, error_flag = 0;
			for(char c:rest)
			{
				if(c == '"')
				{
					inside = 1 - inside;
					continue;
				}
				if(c == ' ' && !inside)
				{
					if(second_flag)
					{
						cout<<"Error : Too many parameters of command copy!"<<endl;
						error_flag = 1;
						break;
					}
					second_flag = 1;
					continue;
				}
				if(!second_flag) name1 += c;
				else name2 += c;
			}
			if(error_flag) continue;
			if(!name2.size())
			{
				cout<<"Error : Too few parameters of command copy!"<<endl;
				continue;
			}
			
			cmd_copy(name1, name2);
		}else if(cmdline.size() >= 6 && cmdline.substr(0, 6)=="makefs")
		{
			if(cmdline.size() <= 7)
			{
				cout<<"Error : Too few parameters of command makefs!"<<endl;
				continue;
			}
			string rest = cmdline.substr(7, cmdline.size() - 7);
			
			string partition = "";
			unsigned int block_size = 0, inode_number = 0;
			
			int second_flag = 0, third_flag = 0, error_flag = 0;
			
			for(char c:rest)
			{
				if(c == ' ')
				{
					if(third_flag)
					{
						cout<<"Error : Too many parameters of command makefs!"<<endl;
						error_flag = 1;
						break;
					}
					if(!second_flag) second_flag = 1;
					else if(!third_flag) third_flag = 1;
					continue;
				}
				if(!second_flag) partition += c;
				else if(!third_flag)
				{
					if(c < '0' || c > '9')
					{
						cout<<"Error : Parameter invalid!"<<endl;
						error_flag = 1;
						break;
					}
					block_size = block_size * 10 + c - '0';
				}else{
					if(c < '0' || c > '9')
					{
						cout<<"Error : Parameter invalid!"<<endl;
						error_flag = 1;
						break;
					}
					inode_number = inode_number * 10 + c - '0';
				}
			}
			if(error_flag) continue;
			
			if(block_size == 0) block_size = 1024;
			if(inode_number == 0) inode_number = 1024;
			
			cmd_mkfs(partition, block_size, inode_number);
		}else if(cmdline.size() >= 6 && cmdline.substr(0, 6)=="delete")
		{
			if(cmdline.size() <= 7)
			{
				cout<<"Error : Too few parameters of command delete!"<<endl;
				continue;
			}
			string rest = cmdline.substr(7, cmdline.size() - 7);
			string filename = "";
			int inside = 0, error_flag = 0;
			
			for(char c:rest)
			{
				if(c == '"')
				{
					inside = 1 - inside;
					continue;
				}
				if(c == ' ' && !inside)
				{
					cout<<"Error : Too many parameters of command delete!"<<endl;
					error_flag = 1;
					break;
					continue;
				}
				filename += c;
			}
			if(error_flag) continue;
			cmd_delete(filename);
		}else if(cmdline.size() >= 7 && cmdline.substr(0, 7)=="makedir")
		{
			if(cmdline.size() <= 8)
			{
				cout<<"Error : Too few parameters of command makedir!"<<endl;
				continue;
			}
			string rest = cmdline.substr(8, cmdline.size() - 8);
			string filename = "";
			int inside = 0, error_flag = 0;
			
			for(char c:rest)
			{
				if(c == '"')
				{
					inside = 1 - inside;
					continue;
				}
				if(c == ' ' && !inside)
				{
					cout<<"Error : Too many parameters of command makedir!"<<endl;
					error_flag = 1;
					break;
					continue;
				}
				filename += c;
			}
			if(error_flag) continue;
			
			cmd_mkdir(filename);
		}else if(cmdline.size() >= 3 && cmdline.substr(0, 3)=="dir")
		{
			if(cmdline.size() <= 4)
			{
				cout<<"Error : Too few parameters of command makedir!"<<endl;
				continue;
			}
			string rest = cmdline.substr(4, cmdline.size() - 4);
			string filename = "";
			int inside = 0, error_flag = 0;
			
			for(char c:rest)
			{
				if(c == '"')
				{
					inside = 1 - inside;
					continue;
				}
				if(c == ' ' && !inside)
				{
					cout<<"Error : Too many parameters of command dir!"<<endl;
					error_flag = 1;
					break;
					continue;
				}
				filename += c;
			}
			if(error_flag) continue;
			
			cmd_dir(filename);
		}else if(cmdline.size() == 4 && cmdline=="exit")
		{
			return 0;
		}else if(cmdline.size() == 4 && cmdline=="help")
		{
			cout<<"Command list:"<<endl;
			cout<<setw(80)<<setiosflags(ios::left)<<"copy des src";
			cout<<"Copy file."<<endl;
			cout<<setw(80)<<setiosflags(ios::left)<<"makefs partition [block size(1024)] [inodes per segment(1024)]";
			cout<<"Make a new file system."<<endl;
			cout<<setw(80)<<setiosflags(ios::left)<<"delete file";
			cout<<"Delete a file or a empty directory."<<endl;
			cout<<setw(80)<<setiosflags(ios::left)<<"dir path";
			cout<<"Get a file list of a directory"<<endl;
		}else{
			cout<<"Error : Unknown command!"<<endl;
		}
	}
	return 0;
}