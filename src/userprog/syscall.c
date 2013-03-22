#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h" 
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "lib/user/syscall.h"
#include "threads/palloc.h"
#ifdef VM
#include "vm/page.h"
#endif

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
static void mmap_handler      (struct intr_frame *f);
static void munmap_handler    (struct intr_frame *f);

uint32_t get_stack_argument(struct intr_frame *f, unsigned int index);
static void validate_user_pointer (const void *pointer);

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
  &close_handler,
  &mmap_handler,
  &munmap_handler
};


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  /* A bad esp value could be used, so validate this first. */
  int32_t *esp = (int32_t*)f->esp;
  validate_user_pointer (esp);
  /* The syscall number is stored at esp. */
  int32_t syscall_number = *esp;

  /* As the system call handler is invoked internally, we can assert that
     this should be true. */
  ASSERT(syscall_number < SYS_NUM_SYSCALLS);

  /* Invoke the correct system call. */
  syscall_handlers[syscall_number](f);
}

/* System calls */
static void
halt_handler (struct intr_frame *f UNUSED)
{
  shutdown_power_off();
}

static void
exit_handler (struct intr_frame *f)
{
  int status = (int)get_stack_argument(f, 0);

  /* Invoke the publicly-visible exit_syscall() function. */
  exit_syscall (status);
}


static void
exec_handler (struct intr_frame *f)
{
  const char *cmd_line = (const char*)get_stack_argument (f, 0); 
  validate_user_pointer ((void *)cmd_line);

  pid_t pid = process_execute(cmd_line);

  f->eax = pid;

}

static void
wait_handler (struct intr_frame *f)
{
	pid_t pid = (pid_t)get_stack_argument (f, 0);
	f->eax = process_wait(pid);
}


static void
create_handler (struct intr_frame *f)
{
  const char *file = (const char*)get_stack_argument (f, 0);
  unsigned initial_size = (unsigned)get_stack_argument (f, 1);

  validate_user_pointer ((void *)file);

  /* We don't allow concurrent filesystem access. */
  start_file_system_access ();

  bool result = filesys_create(file, (off_t)initial_size);

  end_file_system_access ();

  /* Return the result by setting the eax value in the interrupt frame. */
	f->eax = result;
}

static void
remove_handler (struct intr_frame *f)
{
  const char *file = (const char*)get_stack_argument (f, 0);
  validate_user_pointer ((void *)file);

  /* We don't allow concurrent filesystem access. */
  start_file_system_access ();

  bool result = filesys_remove(file);

  end_file_system_access ();

  /* Return the result by setting the eax value in the interrupt frame. */
  f->eax = result;
}

static void
open_handler (struct intr_frame *f)
{
  const char *filename = (const char*)get_stack_argument (f, 0);
  validate_user_pointer ((void *)filename);

  /* We don't allow concurrent filesystem access. */
  start_file_system_access ();

  int fd = -1;
  struct file *file = filesys_open (filename);

  if (file != NULL) {
    struct thread *t = thread_current ();

    // fds 0 and 1 are reserved for stdout and stderr.
    ASSERT(t->proc_info->next_fd > 1);

    // Create the file_descriptor entry to put into the hash table.
    struct file_descriptor *descriptor = malloc (sizeof (struct file_descriptor));
    if (!descriptor)
      exit_syscall (-1);

    descriptor->fd = (t->proc_info->next_fd)++;
    descriptor->file = file;

    fd = descriptor->fd;

    hash_insert (&t->proc_info->file_descriptor_table, &descriptor->hash_elem); 
  }

  end_file_system_access ();

  /* Return the result by setting the eax value in the interrupt frame. */
  f->eax = fd;
}

static void
filesize_handler (struct intr_frame *f)
{
  int fd = (int)get_stack_argument (f, 0);

  /* We don't allow concurrent filesystem access. */
  start_file_system_access ();

  int file_size = 0;
  struct file_descriptor *descriptor = process_get_file_descriptor_struct (fd);
  if (descriptor != NULL)
    file_size = file_length (descriptor->file);

  end_file_system_access ();

  /* Return the result by setting the eax value in the interrupt frame. */
	f->eax = file_size;
}

static void
read_handler (struct intr_frame *f)
{
  int fd = (int)get_stack_argument (f, 0);
  void *buffer = (void *)get_stack_argument (f, 1);
  unsigned size = (unsigned)get_stack_argument (f, 2);
  void *buffer_page;
  struct hash *supplemental_page_table = &thread_current ()->supplemental_page_table;

  validate_user_pointer (buffer);
  validate_user_pointer (buffer+size);

  // Start at buffer, grow check pointers from buffer to size
  // memset buffer to 0. This will cause pagefault if need be.
  for (buffer_page = pg_round_down(buffer); buffer_page <= buffer+size; buffer_page += PGSIZE){
    if (is_in_vstack(buffer_page, f->esp)) {
      struct page p;
      p.vaddr = buffer_page;    
      struct hash_elem *e = hash_find (&thread_current()->supplemental_page_table, &p.hash_elem);
      if (!e) {
        stack_grow(thread_current(), buffer_page);
      }
    }
  }

  if (!supplemental_entry_exists (&thread_current ()->supplemental_page_table, buffer, NULL)
      ||  !supplemental_entry_exists (&thread_current ()->supplemental_page_table, buffer+size, NULL)) {
    exit_syscall(-1);
  }

  if (!supplemental_is_page_writable (supplemental_page_table, buffer))  {
      // print_page_info (supplemental_page_table);
      exit_syscall(-1);
  }
  

  if (fd == 0) {
    uint8_t value = input_getc();
    unsigned bytes_read = 0;

    /* Only store data in the buffer if it is big enough. */
    if (size > 0) {
      *((uint8_t*)buffer) = value;
      bytes_read = 1;
    }

    f->eax = bytes_read;
    return;
  }

  int bytes_read = -1;

  /* We don't allow concurrent filesystem access. */
  start_file_system_access ();

  struct file_descriptor *descriptor = process_get_file_descriptor_struct (fd);
  if (descriptor != NULL) {
    bytes_read = (int)file_read (descriptor->file, buffer, size);
  }

  end_file_system_access ();

  /* Return the result by setting the eax value in the interrupt frame. */
	f->eax = bytes_read;
}

static void
write_handler (struct intr_frame *f)
{
  int fd = (int)get_stack_argument (f, 0);
  const void *buffer = (const void*)get_stack_argument (f, 1);
  unsigned size = (unsigned)get_stack_argument (f, 2);
  validate_user_pointer (buffer + size);
  validate_user_pointer (buffer);
  if (!supplemental_entry_exists (&thread_current ()->supplemental_page_table, buffer, NULL)
      ||  !supplemental_entry_exists (&thread_current ()->supplemental_page_table, buffer+size, NULL)) {
    exit_syscall(-1);
  }

  // Ensure that they're in the supplementary page table too.

  if (fd == 1) {
    putbuf (buffer, size);
    f->eax = size;
    return;
  }

  int bytes_written = -1;

  /* We don't allow concurrent filesystem access. */
  start_file_system_access ();

  struct file_descriptor *descriptor = process_get_file_descriptor_struct (fd);
  if (descriptor != NULL) {
    struct file *file = descriptor->file;

    /* file_write() will handle the case if size is greater than the remaining 
       size of the file. */
    bytes_written = (int)file_write (file, buffer, size);
  }

  end_file_system_access (); 

  /* Return the result by setting the eax value in the interrupt frame. */
	f->eax = bytes_written;
}

static void
seek_handler (struct intr_frame *f)
{
  int fd = (int)get_stack_argument (f, 0);
  unsigned position = (unsigned)get_stack_argument (f, 1);

  /* We don't allow concurrent filesystem access. */
  start_file_system_access ();

  struct file_descriptor *descriptor = process_get_file_descriptor_struct (fd);
  if (descriptor != NULL)
    file_seek (descriptor->file, position);

  end_file_system_access (); 
}

static void
tell_handler (struct intr_frame *f)
{
  int fd = (int)get_stack_argument (f, 0);

  /* We don't allow concurrent filesystem access. */
  start_file_system_access ();

  unsigned position = 0;

  struct file_descriptor *descriptor = process_get_file_descriptor_struct (fd);
  if (descriptor != NULL)
    position = (unsigned)file_tell (descriptor->file);

  end_file_system_access (); 

  /* Return the result by setting the eax value in the interrupt frame. */
  f->eax = position;
}

static void
close_handler (struct intr_frame *f)
{
  int fd = (int)get_stack_argument (f, 0);

  struct file_descriptor *open_file_descriptor = process_get_file_descriptor_struct (fd);
  close_syscall (open_file_descriptor, true);
}

static void
mmap_handler (struct intr_frame *f)
{
  int fd = (int)get_stack_argument (f, 0);
  void *addr = (void *)get_stack_argument (f, 1);
  if (!is_user_vaddr (addr))
    exit_syscall (-1);

  struct thread *cur = thread_current ();

  /* Trying to map stdin or stdout is disallowed. */
  if (addr == 0 || fd == 0 || fd == 1) {
    f->eax = MMAP_ERROR_MAPID;
    return;
  }

  /* Ensure that addr is page-aligned. */
  if ((size_t)addr % PGSIZE != 0) {
    f->eax = MMAP_ERROR_MAPID;
    return;
  }

  /* Locate the file open with fd 'fd' */
  struct file_descriptor *descriptor = process_get_file_descriptor_struct (fd);
  if (descriptor == NULL) {
    f->eax = MMAP_ERROR_MAPID;
    return;
  }

  /* As the memory map stays around even if the original file is
     closed or removed, we need to use our own file handle to the file. */
  start_file_system_access ();
  struct file *file = file_reopen (descriptor->file);

  off_t length = file_length (file);
  end_file_system_access ();
  
  if (length == 0) {
    f->eax = MMAP_ERROR_MAPID;
    return;
  }

  size_t num_pages = length / PGSIZE;
  if (length % PGSIZE)
    num_pages++;

  struct hash *supplemental_page_table = &thread_current ()->supplemental_page_table;

  /* Ensure the space in the user virtual address is not used up. */
  size_t i;
  for (i = 0; i < num_pages; ++i) {
    if (supplemental_entry_exists (supplemental_page_table, addr + i * PGSIZE, NULL)) {
      f->eax = MMAP_ERROR_MAPID;
      return;
    }
  }

  struct mmap_mapping *mapping = malloc (sizeof (struct mmap_mapping));
  if (!mapping)
    exit_syscall (-1);

  mapping->mapid = cur->next_mmapid++;
  mapping->file = file;
  mapping->uaddr = addr;

  /* Add the mapping entries to the supplemental page table */
  size_t bytes_into_file = 0;
  void *uaddr = addr;

  for (i = 0; i < num_pages; ++i) {
    struct page_mmap_info *mmap_info = malloc (sizeof (struct page_mmap_info));
    if (!mmap_info)
      exit_syscall (-1);

    mmap_info->offset = bytes_into_file;
    mmap_info->length = length - bytes_into_file < PGSIZE ? length - bytes_into_file :
                                                                 PGSIZE;
    mmap_info->mapid = mapping->mapid;

    struct page * p = supplemental_create_mmap_page_info (uaddr, mmap_info);
    supplemental_insert_page_info(supplemental_page_table, p);
    bytes_into_file += PGSIZE;
    uaddr += PGSIZE;
  }

  hash_insert (&cur->mmap_table, &mapping->hash_elem);

  f->eax = mapping->mapid;
}

static void
munmap_handler (struct intr_frame *f)
{
  mapid_t mapid = (mapid_t)get_stack_argument (f, 0);

  munmap_syscall (mapid);
}

void
munmap_syscall (mapid_t mapid)
{
  struct hash *mmap_table = &thread_current ()->mmap_table;
  struct mmap_mapping *mapping = mmap_get_mapping (mmap_table, mapid);
  if (!mapping)
    return;

  munmap_syscall_with_mapping (mapping, true);
}

void
munmap_syscall_with_mapping (struct mmap_mapping *mapping, bool should_delete)
{
  ASSERT (mapping->file);

  start_file_system_access ();
  size_t length = file_length (mapping->file);
  end_file_system_access ();

  size_t num_pages = length / PGSIZE;
  if (length % PGSIZE != 0)
    num_pages++;

  size_t i = 0;
  void *uaddr = mapping->uaddr;

  struct hash *supplemental_page_table = &thread_current ()->supplemental_page_table;

  /* Write any pages that have been loaded back to disk. */
  for (i = 0; i < num_pages; ++i) {
    struct page *page_info = NULL;
    ASSERT (supplemental_entry_exists (supplemental_page_table, uaddr, &page_info));

    if (page_info->page_status & PAGE_IN_MEMORY) {
      ASSERT (page_info->page_status & PAGE_MEMORY_MAPPED);
      struct page_mmap_info *mmap_info = (struct page_mmap_info *)page_info->aux;

      void *kaddr = pagedir_get_page (thread_current ()->pagedir, uaddr);
      if (pagedir_is_dirty (thread_current ()->pagedir, page_info->vaddr))
        mmap_write_back_data (mapping, kaddr, mmap_info->offset, mmap_info->length);

      frame_allocator_free_user_page (kaddr, false);
    }

    supplemental_remove_page_entry (supplemental_page_table, uaddr);

    uaddr += PGSIZE;
  }

  if (should_delete) {
    struct mmap_mapping lookup;
    lookup.mapid = mapping->mapid;
    hash_delete (&thread_current ()->mmap_table, &lookup.hash_elem);
  }

  start_file_system_access ();
  file_close (mapping->file);
  end_file_system_access ();

  free (mapping);
}

/* Returns whether a user pointer is valid or not. If it is invalid, the callee
   should free any of its resources and call thread_exit(). */
static void
validate_user_pointer (const void *pointer)
{
  /* Terminate cleanly if the address is invalid. */
	if (pointer == NULL
      || !is_user_vaddr (pointer)
      )
  {
    // Check pointer is not in supplementary page table
    exit_syscall (-1);
    NOT_REACHED ();
  }

}

uint32_t
get_stack_argument(struct intr_frame *f, unsigned int index)
{
  uint32_t *pointer = (uint32_t*)f->esp + index + 1;

  /* We could be given a bad esp, so validate the pointer before
     dereferencing. */
  validate_user_pointer ((void *)pointer);

  return *pointer;
}

/* Publicly visible system calls */

void
close_syscall (struct file_descriptor *file_descriptor,
               bool remove_file_descriptor_table_entry)
{
  start_file_system_access ();

  /* Close the file if it was found. */
  if (file_descriptor != NULL) {
    file_close (file_descriptor->file);

    if (remove_file_descriptor_table_entry) {
      /* Remove the entry from the open files hash table. */
      struct file_descriptor descriptor;
      descriptor.fd = file_descriptor->fd;
      hash_delete (&thread_current ()->proc_info->file_descriptor_table,
                   &descriptor.hash_elem);
    }
    free(file_descriptor);
  }

  end_file_system_access ();
}

void
exit_syscall (int status)
{
  struct thread *t = thread_current ();
  t->proc_info->exit_status = status;

  thread_exit();
}
