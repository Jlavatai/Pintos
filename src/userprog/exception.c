#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "vm/page.h"
#include "vm/mmap.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

struct lock pagefault_lock;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

// Utility function for testing if we need to grow stack
bool is_in_vstack(void *ptr, uint32_t *esp);
/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  lock_init(&pagefault_lock);

  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to task 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  bool stack_growth;  /* True: stack has grown, false: stack has not grown */
  void *fault_addr;  /* Fault address. */


  stack_growth = false; // flag init
  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

    /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;


  // These are the cases we want to look at in detail. For everything else,
  // Goto the pagefault message
  if (not_present && fault_addr && is_user_vaddr(fault_addr)) {

    // /* To implement virtual memory, delete the rest of the function
    //    body, and replace it with code that brings in the page to
    //    which fault_addr refers. */
    void *vaddr = pg_round_down(fault_addr);

    struct thread *t = thread_current ();
    struct page p;
    p.vaddr = vaddr;

    lock_acquire(&pagefault_lock);
    struct hash_elem *e = hash_find (&t->supplemental_page_table, &p.hash_elem);
    lock_release(&pagefault_lock);
    
    // If we don't have a supplementary page table entry
    if (!e) {
      // Check if stack needs to grow
      ASSERT(is_user_vaddr(fault_addr));
      if (is_in_vstack(fault_addr, f->esp)) {
        stack_grow(thread_current(), fault_addr);
        return;
      }
      printf("Not in Supplementary Page Table\n");
      goto page_fault;
    }

    // Supplementary Page Table pointer    
    struct page *page = hash_entry (e, struct page, hash_elem);
    // printf("Page: %X ; page_status: "BYTETOBINARYPATTERN"\n"
    //       , page->vaddr, BYTETOBINARY(page->page_status));
    ASSERT ((page->page_status & PAGE_IN_MEMORY) == 0);
    // printf("Page Status: %i\n", page->page_status);
    switch (page->page_status)
    {
      case PAGE_FILESYS:
      {
        struct page_filesys_info *filesys_info = (struct page_filesys_info *) page->aux;

        struct file *file = filesys_info->file;
        size_t ofs = filesys_info->offset;
        void *kpage = frame_allocator_get_user_page(page, 0, false);
        if(!read_executable_page(file, ofs, kpage, PGSIZE, 0))
            kill(f);
        return;
      }
      break;

      case PAGE_ZERO:
      {
        frame_allocator_get_user_page(page, PAL_ZERO, true);
        return;
      }
      break;

      case PAGE_MEMORY_MAPPED:
      {
        struct page_mmap_info *mmap_info = (struct page_mmap_info *) page->aux;
        void *kpage = frame_allocator_get_user_page(page, PAL_ZERO, true);

        struct mmap_mapping lookup;
        lookup.mapid = mmap_info->mapid;

        struct hash_elem *e = hash_find (&t->mmap_table, &lookup.hash_elem);
        if (!e) {
          frame_allocator_free_user_page(kpage);
          goto page_fault;
        }

        struct mmap_mapping *m = hash_entry (e, struct mmap_mapping, hash_elem);
        struct file *file = m->file;
        size_t ofs = mmap_info->offset;
        size_t length = mmap_info->length;

        file_seek (file, ofs);
        memset (kpage, 0, PGSIZE);

        if (file_read (file, kpage, length) != length) {
          frame_allocator_free_user_page(kpage);
          goto page_fault;
        }

        supplemental_mark_page_in_memory (&t->supplemental_page_table, vaddr);

        return;
      }
      break;
      
      default:
      {
        // printf("Begin Load Page\n");
        // Page is in swap.
        struct swap_entry *swap_info = (struct swap_entry *) page->aux;
        void * kernel_vaddr = frame_allocator_get_user_page(page, 0, true);
        // First Allocate a user page
        // Save it into that page of memory
        swap_load(swap_info, page, kernel_vaddr);
        // Free that page of swap
        swap_free(swap_info);
        // Mark as no longer in swap
        page->page_status &= ~PAGE_SWAP;
        // Mark as in memory
        page->page_status &= ~PAGE_IN_MEMORY;
        // printf("Loaded Page: %X\n", page->vaddr);
        return;
      }
        break;
    }
  }
  page_fault:
    /* Count page faults. */
      page_fault_cnt++;

      printf ("Page fault at %p: %s error %s page in %s context.\n",
              fault_addr,  
              not_present ? "not present" : "rights violation",
              write ? "writing" : "reading",
              user ? "user" : "kernel");


      exit_syscall(-1);  
}

bool
is_in_vstack(void *ptr, uint32_t *esp)
{
  return  ((PHYS_BASE - pg_round_down (ptr)) <= MAX_STACK_SIZE && (uint32_t*)ptr >= (esp - 32));
}