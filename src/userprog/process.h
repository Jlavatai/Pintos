#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

typedef int pid_t;
typedef int tid_t; // Forward declaration for include by thread.h

struct proc_information { 
	struct list_elem elem; // This struct is held as part of a list
	pid_t pid;  // Stores the pid (equivilent to tid) for the process
	int exit_status; // Stores the exit_status for when the process dies
	struct thread *thread; // When the process dies, this is set to NULL.
};


tid_t user_process_execute (const char *file_name);
tid_t process_load_setup(const char *file_name);
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct file_descriptor *process_get_file_descriptor_struct(int fd);

#endif /* userprog/process.h */
