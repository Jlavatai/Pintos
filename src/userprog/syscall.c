#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

static bool validate_user_pointer (void *pointer);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  void *esp = f->esp;
  int32_t syscall_number = *esp;

  thread_exit ();
}

/* Returns whether a user pointer is valid or not. If it is invalid, the callee
   should free any of its resources and call thread_exit(). */
static bool
validate_user_pointer (void *pointer)
{
	return is_user_vaddr () && pagedir_get_page (pointer) != NULL;
}