#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"

typedef int pid_t;

#define UNINITIALISED_EXIT_STATUS 0xdeadbeef
#define EXCEPTION_EXIT_STATUS -1
#define MIN_MMAPID 2

struct proc_information { 
    struct list_elem elem;                  /* To provide linked list functionality */
    pid_t pid;                               /* Stores the pid (equivilent to tid) for the child process */
    int exit_status;                         /* Stores the exit_status for when the process dies */
    struct condition condvar_process_sync;  /* A synchronisation primitive to help synchronise parent and child threads*/
    struct lock anchor;                     /* A lock held during the thread's life */
    bool parent_is_alive;					 /* A boolean to determine if the parent thread is alive */
    bool child_is_alive;					 /* A boolean to determine if the child thread is alive */
    bool child_started_correctly;            /* A boolean to determine if the child thread started correctly (i.e. loaded executable etc) */
    struct hash file_descriptor_table;  	/* Stores descriptors for files opened by the current process. */ 
    int next_fd;                        	/* Stores the next file descriptor for use. */
};

bool install_page (void *upage, void *kpage, bool writable);

pid_t process_execute (const char *file_name);

void process_init (void);
int process_wait (pid_t);
void process_exit (void);
void process_activate (void);

struct file_descriptor *process_get_file_descriptor_struct(int fd);
void start_file_system_access(void);
void end_file_system_access(void);

bool read_executable_page(struct file *file, size_t offset, void *kpage,
                          size_t page_read_bytes, size_t page_zero_bytes);
void stack_grow (struct thread * t, void * fault_ptr);

#endif /* userprog/process.h */
