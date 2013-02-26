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

static struct lock file_system_lock;

void *get_stack_argument(struct intr_frame *f, unsigned int index);
static void validate_user_pointer (void *pointer);
static struct file_descriptor *get_file_descriptor_struct(int fd);

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
halt_handler (struct intr_frame *f UNUSED)
{
  shutdown_power_off();
}

static void
exit_handler (struct intr_frame *f)
{
  int status = (int)get_stack_argument(f, 0);

  exit_syscall (status);
}


static void
exec_handler (struct intr_frame *f)
{

  struct semaphore exec_sema;

  sema_init(&exec_sema, 1);

  

  const char *cmd_line = (const char*)get_stack_argument (f, 0); 

  validate_user_pointer (cmd_line);

  int tid = user_process_execute(cmd_line, &exec_sema);

  sema_down(&exec_sema);

	f->eax = tid;

  sema_up(&exec_sema);
}

static void
wait_handler (struct intr_frame *f)
{
	int pid = (int)get_stack_argument (f, 0);
	f->eax = process_wait(pid);
}


static void
create_handler (struct intr_frame *f)
{
  const char *file = (const char*)get_stack_argument (f, 0);
  unsigned initial_size = (unsigned)get_stack_argument (f, 1);

  validate_user_pointer (file);

  lock_acquire(&file_system_lock);

  bool result = filesys_create(file, (off_t)initial_size);

  lock_release(&file_system_lock);

	f->eax = result;
}

static void
remove_handler (struct intr_frame *f)
{
  const char *file = (const char*)get_stack_argument (f, 0);
  validate_user_pointer (file);

  lock_acquire(&file_system_lock);

  bool result = filesys_remove(file);

  lock_release(&file_system_lock);

  f->eax = result;
}

static void
open_handler (struct intr_frame *f)
{
  const char *filename = (const char*)get_stack_argument (f, 0);
  validate_user_pointer (filename);

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
  int fd = (int)get_stack_argument (f, 0);

  lock_acquire (&file_system_lock);

  int file_size = 0;
  struct file_descriptor *descriptor = process_get_file_descriptor_struct (fd);
  if (descriptor != NULL)
    file_size = file_length (descriptor->file);

  lock_release (&file_system_lock);

	f->eax = file_size;
}

static void
read_handler (struct intr_frame *f)
{
  int fd = (int)get_stack_argument (f, 0);
  void *buffer = get_stack_argument (f, 1);
  unsigned size = (unsigned)get_stack_argument (f, 2);

  validate_user_pointer (buffer);

  // TODO: implement
  if (fd == 0) {
    f->eax = 0;
    return;
  }

  int bytes_read = -1;

  lock_acquire (&file_system_lock);

  struct file_descriptor *descriptor = process_get_file_descriptor_struct (fd);
  if (descriptor != NULL) {
    bytes_read = (int)file_read (descriptor->file, buffer, size);
  }

  lock_release (&file_system_lock);

	f->eax = bytes_read;
}

static void
write_handler (struct intr_frame *f)
{
  int fd = (int)get_stack_argument (f, 0);
  const void *buffer = (const void*)get_stack_argument (f, 1);
  unsigned size = (unsigned)get_stack_argument (f, 2);

  validate_user_pointer (buffer);

  if (fd == 1) {
    putbuf (buffer, size);
    f->eax = size;
    return;
  }

  int bytes_written = -1;

  lock_acquire (&file_system_lock);

  struct file_descriptor *descriptor = process_get_file_descriptor_struct (fd);
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
  int fd = (int)get_stack_argument (f, 0);
  unsigned position = (unsigned)get_stack_argument (f, 1);

  lock_acquire (&file_system_lock);

  struct file_descriptor *descriptor = process_get_file_descriptor_struct (fd);
  if (descriptor != NULL)
    file_seek (descriptor->file, position);

  lock_release (&file_system_lock); 
}

static void
tell_handler (struct intr_frame *f)
{
  int fd = (int)get_stack_argument (f, 0);

  lock_acquire (&file_system_lock);

  unsigned position = 0;

  struct file_descriptor *descriptor = process_get_file_descriptor_struct (fd);
  if (descriptor != NULL)
    position = (unsigned)file_tell (descriptor->file);

  lock_release (&file_system_lock); 

  f->eax = position;
}

static void
close_handler (struct intr_frame *f)
{
  int fd = (int)get_stack_argument (f, 0);

  struct file_descriptor *open_file_descriptor = process_get_file_descriptor_struct (fd);
  close_syscall (open_file_descriptor);
}

/* Returns whether a user pointer is valid or not. If it is invalid, the callee
   should free any of its resources and call thread_exit(). */
static void
validate_user_pointer (void *pointer)
{
  // Terminate cleanly if the address is invalid.
	if (pointer == NULL
      || !is_user_vaddr (pointer)
      || pagedir_get_page(thread_current ()->pagedir, pointer) == NULL) {
    exit_syscall (-1);

    // As we terminate, we shouldn't reach this point.
    NOTREACHED();
  }
}

void *get_stack_argument(struct intr_frame *f, unsigned int index)
{
  uint32_t *pointer = (uint32_t*)f->esp + index + 1;
  validate_user_pointer (pointer);

  return *((int32_t*)pointer);
}

/* Publicly visible system calls */
void
close_syscall (struct file_descriptor *file_descriptor)
{
  lock_acquire (&file_system_lock);

  // Close the file if it was found.
  if (file_descriptor != NULL) {
    file_close (file_descriptor->file);

    // Remove the entry from the open files hash table.
    struct file_descriptor descriptor;
    descriptor.fd = file_descriptor->fd;
    hash_delete (&thread_current ()->file_descriptor_table, &descriptor.hash_elem);
  }

  lock_release (&file_system_lock);
}

void exit_syscall (int status)
{
  struct thread *t = thread_current ();
  t->exit_status = status;

  thread_exit();
}