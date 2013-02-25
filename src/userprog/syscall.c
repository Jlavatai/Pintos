#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#define stack_argument(INTR_FRAME, INDEX, TYPE) (TYPE)*((int32_t*)((INTR_FRAME)->esp) + (INDEX) + 1)
typedef void (*SYSCALL_HANDLER)(struct intr_frame *f);

static void syscall_handler (struct intr_frame *);

static void halt_handler      (struct intr_frame *f);
static void exit_handler      (struct intr_frame *f);
static void exec_handler      (struct intr_frame *f);
static void wait_handler      (struct intr_frame *f);
static void create_handler    (struct intr_frame *f);
static void remove_handler    (struct intr_frame *f);
static void open_handler      (struct intr_frame *f);
static void filesize_handler  (struct intr_frame *f);
static void read_handler      (struct intr_frame *f);
static void write_handler     (struct intr_frame *f);
static void seek_handler      (struct intr_frame *f);
static void tell_handler      (struct intr_frame *f);
static void close_handler     (struct intr_frame *f);

static void validate_user_pointer (void *pointer);
static struct file_descriptor *get_file_descriptor_struct(int fd);

static struct lock file_system_lock;
static const SYSCALL_HANDLER syscall_handlers[] = {
  &halt_handler,
  &exit_handler,
  &exec_handler,
  &wait_handler,
  &create_handler,
  &remove_handler,
  &open_handler,
  &filesize_handler,
  &read_handler,
  &write_handler,
  &seek_handler,
  &tell_handler,
  &close_handler
};

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
  int32_t syscall_number = *((int32_t*)f->esp);

  ASSERT(syscall_number < SYS_NUM_SYSCALLS);
  syscall_handlers[syscall_number](f);
}

// /* System calls */
static void
halt_handler (struct intr_frame *f)
{

}

static void
exit_handler (struct intr_frame *f)
{
  int status = stack_argument(f, 0, int);

  struct thread *t = thread_current ();
  t->exit_status = status;

  thread_exit();
}

static void
exec_handler (struct intr_frame *f)
{
  const char *cmd_line = stack_argument (f, 0, const char*); 

	f->eax = 0;
}

static void
wait_handler (struct intr_frame *f)
{
  int pid = stack_argument (f, 0, int);

	f->eax = 0;
}

static void
create_handler (struct intr_frame *f)
{
  const char *file = stack_argument (f, 0, const char*);
  unsigned initial_size = stack_argument(f, 1, unsigned);

  lock_acquire(&file_system_lock);

  bool result = filesys_create(file, (off_t)initial_size);

  lock_release(&file_system_lock);

	f->eax = result;
}

static void
remove_handler (struct intr_frame *f)
{
  const char *file = stack_argument (f, 0, const char*);

	f->eax = false;
}

static void
open_handler (struct intr_frame *f)
{
  const char *filename = stack_argument (f, 0, const char*);

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

    hash_insert (&t->file_descriptor_table, &descriptor->hash_elem); 
  }

  lock_release (&file_system_lock);

  f->eax = fd;
}

static void
filesize_handler (struct intr_frame *f)
{
  int fd = stack_argument (f, 0, int);

  lock_acquire (&file_system_lock);

  int file_size = 0;
  struct file_descriptor *descriptor = get_file_descriptor_struct (fd);
  if (descriptor != NULL)
    file_size = file_length (descriptor->file);

  lock_release (&file_system_lock);

	f->eax = file_size;
}

static void
read_handler (struct intr_frame *f)
{
  int fd = stack_argument (f, 0, int);
  void *buffer = stack_argument (f, 1, void*);
  unsigned size = stack_argument (f, 2, unsigned);

  // TODO: implement
  if (fd == 0) {
    f->eax = 0;
    return;
  }

  int bytes_read = -1;

  lock_acquire (&file_system_lock);

  struct file_descriptor *descriptor = get_file_descriptor_struct (fd);
  if (descriptor != NULL) {
    bytes_read = (int)file_read (descriptor->file, buffer, size);
  }

  lock_release (&file_system_lock);

	f->eax = bytes_read;
}

static void
write_handler (struct intr_frame *f)
{
  int fd = stack_argument (f, 0, int);
  const void *buffer = stack_argument (f, 1, const void*);
  unsigned size = stack_argument (f, 2, unsigned);

  if (fd == 1) {
    putbuf (buffer, size);
    f->eax = size;
    return;
  }

  int bytes_written = -1;

  lock_acquire (&file_system_lock);

  struct file_descriptor *descriptor = get_file_descriptor_struct (fd);
  if (descriptor != NULL) {
    struct file *file = descriptor->file;
    int write_size = size;
    if (write_size > file_length (file))
      write_size = file_length (file);

    bytes_written = (int)file_write (file, buffer, write_size);
  }

  lock_release (&file_system_lock); 

	f->eax = bytes_written;
}

static void
seek_handler (struct intr_frame *f)
{
  int fd = stack_argument (f, 0, int);
  unsigned position = stack_argument (f, 1, unsigned);

  lock_acquire (&file_system_lock);

  struct file_descriptor *descriptor = get_file_descriptor_struct (fd);
  if (descriptor != NULL)
    file_seek (descriptor->file, position);

  lock_release (&file_system_lock); 
}

static void
tell_handler (struct intr_frame *f)
{
  int fd = stack_argument (f, 0, int);

  lock_acquire (&file_system_lock);

  unsigned position = 0;

  struct file_descriptor *descriptor = get_file_descriptor_struct (fd);
  if (descriptor != NULL)
    position = (unsigned)file_tell (descriptor->file);

  lock_release (&file_system_lock); 

  f->eax = position;
}

static void
close_handler (struct intr_frame *f)
{
  int fd = stack_argument (f, 0, int);

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
  struct thread *t = thread_current ();

  // Terminate cleanly if the address is invalid.
	if (!is_user_vaddr (pointer)) {
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