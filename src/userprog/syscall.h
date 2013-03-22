#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "vm/mmap.h"

/* Struct used when mapping file descriptors to struct file*s. */
struct file_descriptor {
  int fd;
  struct file *file;
  struct hash_elem hash_elem;
};

void syscall_init (void);

/* Publicly visible system calls. */
void close_syscall (struct file_descriptor *file_descriptor,
               		bool remove_file_descriptor_table_entry);
void exit_syscall (int status);
void munmap_syscall_with_mapping (struct mmap_mapping *mapping, bool should_delete);

#endif /* userprog/syscall.h */
