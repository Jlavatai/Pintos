#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/filesys.h"

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

static void validate_user_pointer (void *pointer);
static struct file_descriptor *get_file_descriptor_struct(int fd);

static struct lock file_system_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  // Initialise the lock which is used for filesystem access.
  lock_init(&file_system_lock);
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
    {
      const char *first_arg = (const char*)*(esp + 1);
      validate_user_pointer ((void*)first_arg);

  		f->eax = exec_handler (first_arg);
    }
  		break;

    case SYS_WAIT:
      f->eax = wait_handler (*(esp + 1));
      break;

    case SYS_CREATE:
    {
      const char *first_arg = (const char*)*(esp + 1);
      validate_user_pointer ((void*)first_arg);

      f->eax = create_handler (first_arg, (unsigned)*(esp + 2));
    }
      break;

    case SYS_REMOVE:
    {
      const char *first_arg = (const char*)*(esp + 1);
      validate_user_pointer ((void*)first_arg);

      f->eax = remove_handler (first_arg);
    }
      break;

    case SYS_OPEN:
    {
      const char *first_arg = (const char*)*(esp + 1);
      validate_user_pointer ((void*)first_arg);

      f->eax = open_handler (first_arg);
    }
      break;

    case SYS_FILESIZE:
      f->eax = filesize_handler ((int)*(esp + 1));
      break;

    case SYS_READ:
    {
      void *second_arg = (void*)*(esp + 2);
      validate_user_pointer ((void*)second_arg);

      f->eax = read_handler ((int)*(esp + 1), (void*)*(esp + 2), (unsigned)*(esp + 3));
    }
      break;

    case SYS_WRITE:
    {
      void *second_arg = (void*)*(esp + 1);
      validate_user_pointer ((void*)second_arg);

      f->eax = write_handler ((int)*(esp + 1), (const void*)*(esp + 2), (unsigned)*(esp + 3));
    }
      break;

    case SYS_SEEK:
      seek_handler ((int)*(esp + 1), (unsigned)*(esp + 2));
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
exec_handler (const char *cmd_line UNUSED)
{
	return 0;
}

static int
wait_handler (int pid UNUSED)
{
	return 0;
}

static bool
create_handler (const char *file, unsigned initial_size)
{
  lock_acquire(&file_system_lock);

  bool result = filesys_create(file, (off_t)initial_size);

  lock_release(&file_system_lock);

	return result;
}

static bool
remove_handler (const char *file UNUSED)
{
	return false;
}

static int
open_handler (const char *filename)
{
  lock_acquire (&file_system_lock);

  int fd = -1;
  struct file *file = filesys_open (filename);

  if (file != NULL) {
    struct thread *t = thread_current ();

    // fds 0 and 1 are reserved for stdout and stderr.
    ASSERT(t->next_fd > 1);

    // Create the file_descriptor entry to put into the hash table.
    struct file_descriptor *descriptor = malloc (sizeof (struct file_descriptor));
    descriptor->fd = (t->next_fd)++;
    descriptor->file = file;

    fd = descriptor->fd;

    hash_insert (&t->file_descriptor_table, descriptor); 
  }

  lock_release (&file_system_lock);

  return fd;
}

static int
filesize_handler (int fd)
{
  lock_acquire (&file_system_lock);

  int file_size = 0;
  struct file_descriptor *descriptor = get_file_descriptor_struct (fd);
  if (descriptor != NULL)
    file_size = file_length (descriptor->file);

  lock_release (&file_system_lock);

	return file_size;
}

static int
read_handler (int fd, void *buffer, unsigned size)
{
  // TODO: implement
  if (fd == 0)
    return 0;

  int bytes_read = -1;

  lock_acquire (&file_system_lock);

  struct file_descriptor *descriptor = get_file_descriptor_struct (fd);
  if (descriptor != NULL) {
    bytes_read = (int)file_read (descriptor->file, buffer, size);
  }

  lock_release (&file_system_lock);

	return bytes_read;
}

static int
write_handler (int fd, const void *buffer, unsigned size)
{
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
close_handler (int fd)
{
  lock_acquire (&file_system_lock);

  struct file_descriptor *open_file_descriptor = get_file_descriptor_struct (fd);
  file_close (open_file_descriptor->file);

  lock_release (&file_system_lock);
}

/* Returns whether a user pointer is valid or not. If it is invalid, the callee
   should free any of its resources and call thread_exit(). */
static void
validate_user_pointer (void *pointer)
{
  return;

  struct thread *t = thread_current ();

  // Terminate cleanly if the address is invalid.
	if (!is_user_vaddr (pointer) || pagedir_get_page (t->pagedir, pointer) == NULL) {
    thread_exit ();

    // As we terminate, we shouldn't reach this point.
    NOTREACHED();
  }
}

static struct file_descriptor *
get_file_descriptor_struct(int fd)
{
  // fd 0 and 1 are reserved for stout and stderr respectively.
  if (fd < 2)
    return NULL;

  struct file_descriptor descriptor;
  descriptor.fd = fd;

  struct thread *t = thread_current ();
  struct hash_elem *found_element = hash_find (&t->file_descriptor_table,
                                               &descriptor.hash_elem);
  if (found_element == NULL)
    return NULL;

  struct file_descriptor *open_file_descriptor = hash_entry (found_element,
                                                             struct file_descriptor,
                                                             hash_elem);

  return open_file_descriptor;
}