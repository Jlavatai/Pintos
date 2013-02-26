#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct file_descriptor {
  int fd;
  struct file *file;
  struct hash_elem hash_elem;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct semaphore exec_sema;

#endif /* userprog/process.h */
