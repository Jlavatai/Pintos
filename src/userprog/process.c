#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"

struct argument
{
    char *token;
    struct list_elem token_list_elem;
};

struct stack_setup_data
{
  struct list argv;
  int argc;
};

static struct lock file_system_lock;

static void
cleanup_process_info (struct proc_information *process_info);

unsigned file_descriptor_table_hash_function (const struct hash_elem *e, void *aux);
bool file_descriptor_table_less_func (const struct hash_elem *a,
                                      const struct hash_elem *b,
                                      void *aux);
void file_descriptor_table_destroy_func (struct hash_elem *e, void *aux);

static thread_func start_process NO_RETURN;
static bool esp_not_in_boundaries(void *esp);
static bool load (const char *cmdline, void (**eip) (void), void **esp);
int sum_fileopen(struct thread * t, struct file * f);

unsigned mmap_hash (const struct hash_elem *e, void *aux UNUSED);
bool mmap_less (const struct hash_elem *a,
                const struct hash_elem *b,
                void *aux UNUSED);
void mmap_table_destroy_func (struct hash_elem *e, void *aux);

void
process_init (void)
{
  lock_init(&file_system_lock);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

#define MAX_MEMORY 4096 //4KB

tid_t
process_execute (const char *file_name)
{
    ASSERT(strlen(file_name) <= PGSIZE);
    char *fn_copy;
    char *thread_page;
    char *thread_page_ptr;
    tid_t tid;
    int old_level;
    struct thread *t;
    /* Make a copy of FILE_NAME.
       Otherwise there's a race between the caller and load(). */
    fn_copy     = palloc_get_page (0);
    if (fn_copy == NULL)
    {
        return TID_ERROR;
    }    
    thread_page = palloc_get_page (0);
  
    if (thread_page == NULL)
    {
      palloc_free_page(fn_copy);
      return TID_ERROR;
    }

    memset(thread_page, 0, PGSIZE);

    thread_page_ptr = thread_page;


    struct stack_setup_data* setup_data = NULL;

    setup_data = thread_page_ptr;

    thread_page_ptr += sizeof(struct stack_setup_data);

    list_init(&setup_data->argv);    

    // fn_copy = "run.exe arg1 arg2 arg3..."

    strlcpy (fn_copy, file_name, PGSIZE);

    char *token, *pos;

     /*Tokenize file name copy to get the single arguments.*/

    // printf("Before argc: %d\n", setup_data->argc);
    for (token = strtok_r (fn_copy, " ", &pos); token != NULL;
            token = strtok_r (NULL, " ", &pos))
    {
        struct argument *arg = NULL;
        arg = (struct argument *)thread_page_ptr;
        thread_page_ptr += sizeof(struct argument);

        ASSERT (thread_page_ptr - thread_page <= PGSIZE);

        arg->token = token;
        list_push_front(&setup_data->argv, &arg->token_list_elem);
        setup_data->argc++;
    }
    


    struct argument *fst_arg = list_entry(list_back(&setup_data->argv), struct argument, token_list_elem);

    // Setup process information shared structure
    // Initialise and Put together the information struct
    struct proc_information * proc_info = calloc(1, sizeof(struct proc_information));
    if (proc_info == NULL) {
      palloc_free_page(fn_copy);
      palloc_free_page(thread_page);
    	return TID_ERROR;
    }
    // Ensure the calloc call worked correctly
    ASSERT(proc_info);
    proc_info->pid = tid;
    // Initialise Anchor
    lock_init(&proc_info->anchor);
    // Initialise life condition
    cond_init(&proc_info->condvar_process_sync);
    proc_info->exit_status = UNINITIALISED_EXIT_STATUS;
    proc_info->child_is_alive = true;
    proc_info->parent_is_alive = true;
    proc_info->child_started_correctly = false; // Until it has started

    /* Set up file descriptor table. */
    hash_init (&proc_info->file_descriptor_table,
               &file_descriptor_table_hash_function,
               &file_descriptor_table_less_func,
               NULL);
    proc_info->next_fd = 2;

    old_level = intr_disable ();
    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create (fst_arg->token, PRI_DEFAULT, start_process, setup_data);
    if (tid == TID_ERROR)
	{
    palloc_free_page (pg_round_down(fn_copy));
    palloc_free_page (pg_round_down(thread_page));
	} else {
		proc_info->pid = tid;
		t = thread_lookup(tid);
		// Store a pointer to this structure inside the thread's information struct
		t->proc_info = proc_info;
		// Store this in the parent's child struct
		list_push_back(&thread_current()->children, &proc_info->elem);
	}
    intr_set_level(old_level);

    // We want to collect an exit_status of -1, and return it, if thread cannot start
    // Get the thread structure

  	lock_acquire(&proc_info->anchor);
  	if (proc_info->exit_status == (int)UNINITIALISED_EXIT_STATUS)
  		cond_wait(&proc_info->condvar_process_sync, &proc_info->anchor);
  	if (!proc_info->child_started_correctly)
  		tid = EXCEPTION_EXIT_STATUS;
  	lock_release(&proc_info->anchor);

    return tid;
}


/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *setup_data_)
{

   /*The struct setup_data contains a pointer to the arguments and the arg count*/

  struct stack_setup_data *setup_data = (struct stack_setup_data *) setup_data_;


  struct intr_frame if_;
  bool success;

   /*Saving the first argument, which will be needed
    to free the memory page at the end of the setup*/

  struct argument *fst_arg = list_entry(list_back(&setup_data->argv), struct argument, token_list_elem);
  char *fst_arg_saved = fst_arg->token; 


  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (fst_arg_saved, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  
  struct thread *cur = thread_current();


  // Signal the parent process about the execution's validity

  lock_acquire(&cur->proc_info->anchor);
  cur->proc_info->exit_status = EXCEPTION_EXIT_STATUS; // This should be the default
  cur->proc_info->child_started_correctly = success;
  cond_signal(&cur->proc_info->condvar_process_sync, &cur->proc_info->anchor);
  lock_release(&cur->proc_info->anchor);

  // Exit the process if the file failed to load
  if (!success) {
    palloc_free_page(fst_arg_saved);
    palloc_free_page(setup_data_);
	  thread_exit ();
  }

  struct list_elem *e;

  /*Beginning the stack setup*/

  /*The string are copied by first decreasing the esp by the length of
    the string, and then using strlcpy to actually copying it.
    Moreover, once the string is copied, the original ptr to the string
    is replaced with the new ptr to the string in the stack. This will
    allow us to iterate over the same string without allocating any resource*/
  // printf("Created: argc: %d\n", setup_data->argc);
  for (e = list_begin (&setup_data->argv); e != list_end (&setup_data->argv);
          e = list_next (e))
  {
      struct argument *arg = list_entry (e, struct argument, token_list_elem);
      char *curr_arg = arg->token;
      if_.esp -= (strlen(curr_arg) + 1);
      // if(esp_not_in_boundaries(if_.esp)) {
      //   palloc_free_page(pg_round_down(fst_arg_saved));
      //   palloc_free_page(pg_round_down(setup_data_));
      //   thread_exit();
      // }
      strlcpy (if_.esp, curr_arg, strlen(curr_arg) + 1);
      arg->token = if_.esp;
  }

  /*Pushing a 0 byte to provide alignment*/

  uint8_t align = 0;
  if_.esp -= (sizeof(uint8_t));
  // if(esp_not_in_boundaries(if_.esp)) {
  //   palloc_free_page(pg_round_down(fst_arg_saved));
  //   palloc_free_page(pg_round_down(setup_data_));
  //   thread_exit();
  // }
  *(uint8_t *)if_.esp = align;

  /*Pushing a null pointer to respect the convention argv[argc] = NULL*/

  char *last_arg_ptr  = NULL;
  if_.esp-= (sizeof(char *));
  // if(esp_not_in_boundaries(if_.esp)) {
  //   palloc_free_page(pg_round_down(fst_arg_saved));
  //   palloc_free_page(pg_round_down(setup_data_));
  //   thread_exit();
  // }
  *(int32_t *)if_.esp = (int32_t)last_arg_ptr;

   /*Iterating over the same list pushing the ptrs to the arguments strings
    on the stack*/

  for (e = list_begin (&setup_data->argv); e != list_end (&setup_data->argv);)
  {
  	struct argument *arg = list_entry (e, struct argument, token_list_elem);
  	char *curr_arg = arg->token;
  	if_.esp -= (sizeof(char*));
  	*(int32_t *)if_.esp = (int32_t)curr_arg;
  	e = list_next (e);
  }

  /*Pushing the ptr to argv*/

  char **fst_arg_ptr = if_.esp;
  if_.esp -= (sizeof(char **));
  // if(esp_not_in_boundaries(if_.esp)) {
  //   palloc_free_page(pg_round_down(fst_arg_saved));
  //   palloc_free_page(pg_round_down(setup_data_));
  //   thread_exit();
  //}

  *(int32_t *)if_.esp = (int32_t)fst_arg_ptr;
   
  /*Pushing argc*/
  if_.esp -=(sizeof(setup_data->argc));
  // if(esp_not_in_boundaries(if_.esp)) {
  //   palloc_free_page(pg_round_down(fst_arg_saved));
  //   palloc_free_page(pg_round_down(setup_data_));
  //   thread_exit();
  // }
  *(int32_t *)if_.esp = setup_data->argc;
     

   /*Pushing the fake return address*/
  void *fake_return  = 0;
  if_.esp -= (sizeof(void *));
  // if(esp_not_in_boundaries(if_.esp)) {
  //   palloc_free_page(pg_round_down(fst_arg_saved));
  //   palloc_free_page(pg_round_down(setup_data_));
  //   thread_exit();
  // }
  *(int32_t *)if_.esp = (int32_t)fake_return;


  // Free all the data used to setup the thread
  palloc_free_page(pg_round_down(fst_arg_saved));
  palloc_free_page(pg_round_down(setup_data_));

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */

    asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
    NOT_REACHED ();
}

static bool
esp_not_in_boundaries(void *esp)
{
  return ((uint32_t *)PHYS_BASE - (uint32_t *)esp) > MAX_MEMORY;
}


/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
	struct thread * cur = thread_current();
	struct list_elem * e;
	// Lookup child_tid in children
    for (e = list_begin (&cur->children); e != list_end (&cur->children);
	     e = list_next (e))
	{
		struct proc_information *procInfo = list_entry (e, struct proc_information, elem);
		if (procInfo->pid == child_tid) {
			lock_acquire(&procInfo->anchor);
			// If we were blocked by acquire, we might have deleted the thread struct
			if (procInfo->child_is_alive)
				cond_wait(&procInfo->condvar_process_sync, &procInfo->anchor);

			// Store the exit_status on the stack due to memory being freed
			int exit_status = procInfo->exit_status;

			// Delete from process list so the next time returns -1
			list_remove(e);

			// Atomic operation
			lock_release(&procInfo->anchor);

      // Free the memory
      cleanup_process_info(procInfo);

      // return exit_status
      return exit_status;
    }
  }
    return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{

    struct thread *cur = thread_current ();
    struct list_elem *e;
    uint32_t *pd;
    pid_t pid = thread_current()->tid;  

    if (cur->proc_info) {
      printf ("%s: exit(%d)\n", cur->name, cur->proc_info->exit_status);

      /* Destroy the file descriptor table */      
      hash_destroy(&cur->proc_info->file_descriptor_table,
                   &file_descriptor_table_destroy_func);

      lock_acquire(&cur->proc_info->anchor);
      cur->proc_info->child_is_alive = false;
      if (cur->proc_info->parent_is_alive) {
        cond_signal(&cur->proc_info->condvar_process_sync, &cur->proc_info->anchor);
        lock_release(&cur->proc_info->anchor);
      }
      else {
        cleanup_process_info(cur->proc_info);
      }
    }

    /* If this process is holding the filesystem lock, release it. */
    if (file_system_lock.holder == cur)
      lock_release (&file_system_lock);

    pd = cur->pagedir;

    // Delete any child processes information structures
    for (e = list_begin (&cur->children); e != list_end (&cur->children);)
    {
      struct proc_information *procInfo = list_entry (e, struct proc_information, elem);
      e = list_next (e);
      list_remove(&procInfo->elem);
      if (!procInfo->child_is_alive)
        cleanup_process_info(procInfo);
      else {
        procInfo->parent_is_alive = false;
      }
    }

    // Close the executable file, if the file is still open somewhere, writes
    // will still be disabled.
    if (cur->file) {
      start_file_system_access ();
      file_close(cur->file);
      end_file_system_access ();
    }

  #ifdef VM

    hash_destroy (&cur->supplemental_page_table,
                  supplemental_page_table_destroy_func);
    hash_destroy (&cur->mmap_table,
                  mmap_table_destroy_func);
  #endif

    /* Destroy the current process's page directory and switch back
       to the kernel-only page directory. */
    if (pd != NULL)
    {
        /* Correct ordering here is crucial.  We must set
           cur->pagedir to NULL before switching page directories,
           so that a timer interrupt can't switch back to the
           process page directory.  We must activate the base page
           directory before destroying the process's page
           directory, or our active page directory will be one
           that's been freed (and cleared). */
        cur->pagedir = NULL;

        pagedir_activate (NULL);
        pagedir_destroy (pd);
    }
}

static void
cleanup_process_info (struct proc_information *process_info)
{
    free(process_info);
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
    struct thread *t = thread_current ();

    /* Activate thread's page tables. */
    pagedir_activate (t->pagedir);

    /* Set thread's kernel stack for use in processing
       interrupts. */
    tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
    struct thread *t = thread_current ();
    struct Elf32_Ehdr ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    /* Allocate and activate page directory. */
    t->pagedir = pagedir_create ();
    if (t->pagedir == NULL)
        goto done;

#ifdef VM
    hash_init (&t->supplemental_page_table,
               supplemental_page_table_hash,
               supplemental_page_table_less,
               NULL);

    hash_init (&t->mmap_table, mmap_hash, mmap_less, NULL);
    t->next_mmapid = MIN_MMAPID;
#endif

    process_activate ();

    /* Open executable file. */
    start_file_system_access ();
    file = filesys_open (file_name);
    end_file_system_access ();
    if (file == NULL)
    {
        printf ("load: %s: open failed\n", file_name);
        goto done;
    }


    /* Read and verify executable header. */
    if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
            || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
            || ehdr.e_type != 2
            || ehdr.e_machine != 3
            || ehdr.e_version != 1
            || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
            || ehdr.e_phnum > 1024)
    {
        printf ("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++)
    {
        struct Elf32_Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length (file))
            goto done;
        file_seek (file, file_ofs);

        if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
            /* Ignore this segment. */
            break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
            goto done;
        case PT_LOAD:
            if (validate_segment (&phdr, file))
            {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0)
                {
                    /* Normal segment.
                       Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                  - read_bytes);
                }
                else
                {
                    /* Entirely zero.
                       Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
                if (!load_segment (file, file_page, (void *) mem_page,
                                   read_bytes, zero_bytes, writable))
                    goto done;
            }
            else
                goto done;
            break;
        }
    }

    /* Set up stack. */
    if (!setup_stack (esp))
        goto done;

    /* Start address. */
    *eip = (void ( *) (void)) ehdr.e_entry;

    success = true;

    // Deny writes to a currently running executable
    file_deny_write(file);

done:

    /* We close the file when it finishes executing. */
    t->file = file;

    return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (Elf32_Off) file_length (file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr ((void *) phdr->p_vaddr))
        return false;
    if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

    /* It's okay. */
    return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT (pg_ofs (upage) == 0);
    ASSERT (ofs % PGSIZE == 0);

    file_seek (file, ofs);

    size_t page_index = 0;
    struct hash *supplemental_page_table = &thread_current ()->supplemental_page_table;

    while (read_bytes > 0 || zero_bytes > 0)
    {
        /* Calculate how to fill this page.
           We will read PAGE_READ_BYTES bytes from FILE
           and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        bool should_read_into_page = true;
        enum page_status status;

        if (page_read_bytes == PGSIZE) {
          should_read_into_page = false;
          status = PAGE_FILESYS;
        }

        if (page_zero_bytes == PGSIZE) {
          should_read_into_page = false;
          status = PAGE_ZERO;
        }

        /* Get a user page */
        if (should_read_into_page) {
          uint8_t *kpage = frame_allocator_get_user_page(upage, 0, true);

          if (!load_executable_page (file, ofs + page_index * PGSIZE,
                                     kpage, page_read_bytes, page_zero_bytes))
            return false;

          insert_in_memory_page_info (supplemental_page_table, upage, false);
        }
        else {
          switch (status) {
            case PAGE_FILESYS:
            {
              struct page_filesys_info *filesys_info = malloc(sizeof (struct page_filesys_info));
              filesys_info->file = file;
              filesys_info->offset = page_index * PGSIZE;

              insert_filesys_page_info (supplemental_page_table, upage, filesys_info);
            }
            break;

            case PAGE_ZERO:
              insert_zero_page_info (supplemental_page_table, upage);
            break;

            default:
            break;
          }
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;

        ++page_index;
    }
    return true;
}

bool
load_executable_page(struct file *file, size_t offset, void *kpage, size_t page_read_bytes,
                     size_t page_zero_bytes)
{
  file_seek (file, offset);

  /* Load this page. */
  if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
  {
      return false;
  }

  memset (kpage + page_read_bytes, 0, page_zero_bytes);

  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
    uint8_t *kpage;
    bool success = false;

    void *user_vaddr = ((uint8_t *) PHYS_BASE) - PGSIZE;
    kpage = frame_allocator_get_user_page(user_vaddr, PAL_ZERO, true);
    struct thread* cur = thread_current();
    insert_zero_page_info (&cur->supplemental_page_table, user_vaddr);

    if (kpage != NULL) 
    {
      *esp = PHYS_BASE;
      success = true;
    }
    return success;
} 

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
    struct thread *t = thread_current ();

    /* Verify that there's not already a page at that virtual
       address, then map our page there. */
    return (pagedir_get_page (t->pagedir, upage) == NULL
            && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* File descriptor functions. */

struct file_descriptor *
process_get_file_descriptor_struct(int fd)
{
  // fd 0 and 1 are reserved for stout and stderr respectively.
  if (fd < 2)
    return NULL;

  struct file_descriptor descriptor;
  descriptor.fd = fd;

  struct thread *t = thread_current ();
  struct hash_elem *found_element = hash_find (&t->proc_info->file_descriptor_table,
                                               &descriptor.hash_elem);
  if (found_element == NULL)
    return NULL;

  struct file_descriptor *open_file_descriptor = hash_entry (found_element,
                                                             struct file_descriptor,
                                                             hash_elem);

  return open_file_descriptor;
}

unsigned
file_descriptor_table_hash_function (const struct hash_elem *e, void *aux UNUSED)
{
  struct file_descriptor *descriptor =  hash_entry (e, struct file_descriptor, hash_elem);

  return descriptor->fd;
}

bool
file_descriptor_table_less_func (const struct hash_elem *a,
                           const struct hash_elem *b,
                           void *aux UNUSED)
{
  struct file_descriptor *descriptor_a =  hash_entry (a,
                                                      struct file_descriptor,
                                                      hash_elem);
  struct file_descriptor *descriptor_b =  hash_entry (b,
                                                      struct file_descriptor,
                                                      hash_elem);

  return descriptor_a->fd < descriptor_b->fd;
}

void
file_descriptor_table_destroy_func (struct hash_elem *e, void *aux UNUSED)
{
  struct file_descriptor *descriptor =  hash_entry (e,
                                                    struct file_descriptor,
                                                    hash_elem);

  ASSERT (descriptor->file != NULL);

  // Close the file descriptor for the open file.
  close_syscall (descriptor, false);
}

void
start_file_system_access(void)
{
  lock_acquire(&file_system_lock);
}

void
end_file_system_access(void)
{
  lock_release(&file_system_lock);
}

unsigned
mmap_hash (const struct hash_elem *e, void *aux UNUSED)
{
  const struct mmap_mapping *mapping = hash_entry (e, struct mmap_mapping, hash_elem);
  return hash_bytes (&mapping->mapid, sizeof (mapping->mapid));
}

bool
mmap_less (const struct hash_elem *a,
           const struct hash_elem *b,
           void *aux UNUSED)
{
  const struct mmap_mapping *mapping_a = hash_entry (a, struct mmap_mapping, hash_elem);
  const struct mmap_mapping *mapping_b = hash_entry (b, struct mmap_mapping, hash_elem);

  return mapping_a->mapid < mapping_b->mapid;
}

void
mmap_table_destroy_func (struct hash_elem *e, void *aux)
{
  struct mmap_mapping *mapping =  hash_entry (e,
                                              struct mmap_mapping,
                                              hash_elem);

  ASSERT (mapping->file != NULL);

  // Close the file descriptor for the open file.
  close_syscall (mapping->file, false);  
}
