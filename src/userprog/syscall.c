#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h" 

static void syscall_handler (struct intr_frame *);

static void halt_handler (void);
void exit_handler (int status);
static int exec_handler (const char *cmd_line);
static int wait_handler (int pid);
static bool create_handler (const char *file, unsigned initial_size);
static bool remove_handler (const char *file);
static int open_handler (const char *file);
static int filesize_handler (int fd);
static int read_handler (int fd, void *buffer, unsigned size);
static int write_handler (int fd, const void *buffer, unsigned size);
static void seek_handler (int fd, unsigned position);
static unsigned tell_handler (int fd);
static void close_handler (int fd);

static bool validate_user_pointer (void *pointer);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int32_t *esp = f->esp;
  int32_t syscall_number = *esp;

  switch (syscall_number)
  {
  	case SYS_HALT:
  		halt_handler ();
  		break;

  	case SYS_EXIT:
  		exit_handler (*(esp + 1));
  		break;

  	case SYS_EXEC:
  		f->eax = exec_handler ((const char*)*(esp + 1));
  		break;

    case SYS_WAIT:
      f->eax = wait_handler (*(esp + 1));
      break;

    case SYS_CREATE:
      f->eax = create_handler ((const char*)*(esp + 2), (unsigned)*(esp + 1));
      break;

    case SYS_REMOVE:
      f->eax = remove_handler ((const char*)*(esp + 1));
      break;

    case SYS_OPEN:
      f->eax = open_handler ((const char*)*(esp + 1));
      break;

    case SYS_FILESIZE:
      f->eax = filesize_handler ((int)*(esp + 1));
      break;

    case SYS_READ:
      f->eax = read_handler ((int)*(esp + 3), (void*)*(esp + 2), (unsigned)*(esp + 1));
      break;

    case SYS_WRITE:
      f->eax = write_handler ((int)*(esp + 1), (const void*)*(esp + 2), (unsigned)*(esp + 3));
      break;

    case SYS_SEEK:
      seek_handler ((int)*(esp + 2), (unsigned)*(esp + 1));
      break;

    case SYS_TELL:
      f->eax = tell_handler (*(esp + 1));
      break;

    case SYS_CLOSE:
      close_handler (*(esp + 1));
      break;
  }
}

// /* System calls */
static void
halt_handler (void)
{

}

void
exit_handler (int status)
{
  struct thread *t = thread_current ();
  t->exit_status = status;

  thread_exit();
}

static int
exec_handler (const char *cmd_line )
{
	int proc_ident = process_execute(cmd_line);

  sema_down(&exec_sema);

  return proc_ident;

}

static int
wait_handler (int pid)
{
	return process_wait(pid);
}

static bool
create_handler (const char *file UNUSED, unsigned initial_size UNUSED)
{
	return false;
}

static bool
remove_handler (const char *file UNUSED)
{
	return false;
}

static int
open_handler (const char *file UNUSED)
{
  return 0;
}

static int
filesize_handler (int fd UNUSED)
{
	return 0;
}

static int
read_handler (int fd UNUSED, void *buffer UNUSED, unsigned size UNUSED)
{
	return 0;
}

static int
write_handler (int fd, const void *buffer, unsigned size)
{

 // printf("Printing buf %s\n", (char *) buffer );

  if (fd == 1) {
    putbuf (buffer, size);
    return size;
  }

	return 0;
}

static void
seek_handler (int fd UNUSED, unsigned position UNUSED)
{

}

static unsigned
tell_handler (int fd UNUSED)
{
	return 0;
}

static void
close_handler (int fd UNUSED)
{
}

/* Returns whether a user pointer is valid or not. If it is invalid, the callee
   should free any of its resources and call thread_exit(). */
static bool
validate_user_pointer (void *pointer)
{
  struct thread *t = thread_current ();

	return is_user_vaddr (pointer) && pagedir_get_page (t->pagedir, pointer) != NULL;
}