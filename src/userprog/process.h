#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

typedef int tid_t; // Forward declaration for include by thread.h


#define UNINITIALISED_EXIT_STATUS 0xdeadbeef
#define LOAD_EXCEPTION 0xbadbad
#define DEFAULT_EXIT_STATUS -1

struct proc_information { 
    struct list_elem elem;                  /* To provide linked list functionality */
    tid_t pid;                               /* Stores the pid (equivilent to tid) for the child process */
    int exit_status;                         /* Stores the exit_status for when the process dies */
    struct condition condvar_process_sync;  /* A synchronisation primitive to help synchronise parent and child threads*/
    struct lock anchor;                     /* A lock held during the thread's life */
    bool parent_is_alive;					 /* A boolean to determine if the parent thread is alive */
    bool child_is_alive;					 /* A boolean to determine if the child thread is alive */
    struct hash file_descriptor_table;  	/* Stores descriptors for files opened by the current process. */ 
    int next_fd;                        	/* Stores the next file descriptor for use. */
};


tid_t user_process_execute (const char *file_name);
tid_t process_load_setup(const char *file_name);
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct file_descriptor *process_get_file_descriptor_struct(int fd);

#endif /* userprog/process.h */
