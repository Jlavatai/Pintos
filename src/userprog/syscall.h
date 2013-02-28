#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "userprog/process.h"

void syscall_init (void);

/* Publicly visible system calls. */
void close_syscall (struct file_descriptor *file_descriptor);
void exit_syscall (int status);

#endif /* userprog/syscall.h */
