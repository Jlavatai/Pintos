#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include <hash.h>
#include "filesys/off_t.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

/* Struct used when mapping file descriptors to struct file*s. */
struct file_descriptor {
  int fd;
  struct file *file;
  struct hash_elem hash_elem;
};

/* Block device that contains the file system. */
struct block *fs_device;

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size);
struct file *filesys_open (const char *name);
bool filesys_remove (const char *name);


#endif /* filesys/filesys.h */
