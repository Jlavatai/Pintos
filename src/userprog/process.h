#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t user_process_execute (const char *file_name);
tid_t process_load_setup(const char *file_name);
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct file_descriptor *process_get_file_descriptor_struct(int fd);

#endif /* userprog/process.h */
