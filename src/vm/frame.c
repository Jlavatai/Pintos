#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

#include <debug.h>

#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"


void frame_map(void * frame_addr, void *vaddr, bool writable);
void frame_unmap(void *frame_addr);

static unsigned frame_hash(const struct hash_elem *e, void *aux);
static bool frame_less (const struct hash_elem *a,
            const struct hash_elem *b,
            void *aux);
static void *frame_allocator_evict_page(void);
static struct frame *frame_allocator_choose_eviction_frame(void);
static void frame_allocator_save_frame (struct frame*);

struct lock frame_table_lock;
struct lock frame_allocation_lock;

/* Initialises the frame table. */
void
frame_table_init(void)
{
  hash_init (&frame_table, frame_hash, frame_less, NULL);
  lock_init (&frame_table_lock);
  lock_init (&frame_allocation_lock); // Must prevent multiple pages allocating at the same time to avoid eviction problems
}

void frame_map(void * frame_addr, void *vaddr, bool writable)
{ 
  struct page *new_page = NULL;
  new_page = malloc (sizeof(struct page));
  if(new_page == NULL) 
  {
    PANIC("Failed to malloc memory for struct page");
  }

  new_page->writable = writable;

  new_page->vaddr = vaddr;

  struct frame *new_fr = NULL;
  new_fr = malloc (sizeof(struct frame));
  if(new_fr == NULL) 
  {
    PANIC("Failed to malloc memory for struct frame");
  }
  new_fr->page = new_page;
  new_fr->frame_addr = frame_addr;
  new_fr->owner_id = thread_current()->tid;
  new_fr->unused_count = 0;

  lock_acquire (&frame_table_lock);
  hash_insert(&frame_table, &new_fr->hash_elem);
  lock_release (&frame_table_lock);
}

void frame_unmap(void *frame_addr)
{
  struct frame f;
  f.frame_addr = frame_addr;

  lock_acquire (&frame_table_lock);
  hash_delete (&frame_table, &f.hash_elem);
  lock_release (&frame_table_lock);
}


/* Hash function for the frame table. */
static unsigned
frame_hash(const struct hash_elem *e, void *aux UNUSED)
{
  const struct frame *f = hash_entry (e, struct frame, hash_elem);

  return hash_bytes (&f->frame_addr, sizeof (f->frame_addr));
}

static bool
frame_less (const struct hash_elem *a, const struct hash_elem *b,
      void *aux UNUSED)
{
  const struct frame *frame_a = hash_entry (a, struct frame, hash_elem);
  const struct frame *frame_b = hash_entry (b, struct frame, hash_elem);

  return frame_a->frame_addr < frame_b->frame_addr;
}

/* Getting user frames */
void *
frame_allocator_get_user_page(void *user_vaddr, enum palloc_flags flags,
                bool writable)
{
  return frame_allocator_get_user_page_multiple(user_vaddr, 1, flags, writable);
}

void *
frame_allocator_get_user_page_multiple(void *user_vaddr,
                     unsigned int num_frames,
                     enum palloc_flags flags,
                     bool writable)
{
  ASSERT(is_user_vaddr(user_vaddr));

  lock_acquire(&frame_allocation_lock);
  void *kernel_vaddr = palloc_get_page (PAL_USER | flags);

  if (kernel_vaddr == NULL) {
    // Evict and allocate a new page
    frame_allocator_evict_page();
    printf("Evicted a Page");
    kernel_vaddr = palloc_get_page (PAL_USER | flags);
    if (kernel_vaddr == NULL) {
      frame_allocator_evict_page();
      kernel_vaddr = palloc_get_page (PAL_USER | flags);
      if (kernel_vaddr == NULL) {
        frame_allocator_evict_page();
        kernel_vaddr = palloc_get_page (PAL_USER | flags);
        if (kernel_vaddr == NULL) {
          PANIC("Sir. I've failed, and failed badly. I tried my best Sir.");
        }
      }
    }
  }

  size_t i;

  /* Map all of the frames used to their page virtual addresses. */
  for (i = 0; i < num_frames; ++i) {
    void *page_user_vaddr = user_vaddr + i * PGSIZE;
    void *page_kernel_vaddr = kernel_vaddr + i * PGSIZE;

    ASSERT(is_user_vaddr(page_user_vaddr));
    
    if (!install_page(page_user_vaddr, page_kernel_vaddr, writable)) {
      PANIC("Could not install user page %p", page_user_vaddr);
    }

    frame_map (page_kernel_vaddr, page_user_vaddr, writable);
  }

  lock_release(&frame_allocation_lock);

  return kernel_vaddr;
}

void
frame_allocator_free_user_page(void *kernel_vaddr)
{
  palloc_free_page (kernel_vaddr);

  lock_acquire (&frame_allocation_lock);

  uint32_t *pd = thread_current ()->pagedir;
  struct frame lookup;
  lookup.frame_addr = kernel_vaddr;

  struct hash_elem *e = hash_find (&frame_table, &lookup.hash_elem);
  if (!e)
    PANIC("Frame doesn't exist in frame table.");

  struct frame *f = hash_entry (e, struct frame, hash_elem);
  if (!f)
    PANIC ("Could not load frame info from frame table");
  
  pagedir_clear_page (pd, f->page->vaddr);
  frame_unmap (kernel_vaddr);  

  lock_release (&frame_allocation_lock);
}

static void *
frame_allocator_evict_page(void) {
  struct frame * f = frame_allocator_choose_eviction_frame();
  // Allocate some swap memory for this frame
  frame_allocator_save_frame (f);
}

static void frame_allocator_save_frame (struct frame* f) {
  // Lookup owner id
  tid_t thread_id = f->owner_id;
  // Get the corresponding thread
  struct thread* t = thread_lookup(thread_id);
  if(!t)
    PANIC("Corruption of frame table");

  printf("Evicting Page: %X\n", f->page->vaddr); 
  ASSERT(f->page);


  bool dirtyFlag = pagedir_is_dirty(t->pagedir, f->page->vaddr);
  // If the page is dirty, write it back to the
  // file it came from.
  // If the page is not dirty, then it is stack
  //   so write it to swap

  if (dirtyFlag &&
      f->page->page_status == PAGE_MEMORY_MAPPED) {
      // TODO: Uncomment when Alex's updated stuff.
      // struct page_mmap_info * mmap_info = (struct page_mmap_info *)f->page->aux;

      // file_seek (mmap_info->file, mmap_info->offset);

      // file_write (mmap_info->file, 
      //             f->page->vaddr,
      //             mmap_info->length);
  } else if (dirtyFlag) {
    // Allocate some Swap memory
    struct swap_entry *s = swap_alloc();
    if (!s) {
      PANIC("Frame Eviction: No Swap Memory left!");
    }
    // Set the page status to swap
    f->page->page_status = PAGE_SWAP;
    f->page->writable = false;
    f->page->aux = s;
    // Save the data into swap.
    swap_save(s, (void*)f->frame_addr);
  }
  // Free the page
  frame_allocator_free_user_page(f->page->vaddr);

}

struct frame * frame_allocator_choose_eviction_frame(void) {
  struct hash_iterator i;
  struct thread *t;
  struct frame * eviction_candidate;
  int32_t least_used = 0;

  // We aim to use pseudo LRU replacement.
  // When we choose to evict, find the oldest page which hasn't
  // been accessed since the last eviction. We do
  // this by choosing the page which has the greatest 
  // unused_count, which increments when it is unused in this 
  // algorithm.
  hash_first (&i, &frame_table);
  // Iterate through the frame table.
  while(hash_next (&i)) {
    // Get the frame that it is equivalent to
    struct frame *f = hash_entry (hash_cur (&i), struct frame, hash_elem);
    // Get the owning thread
    t = thread_lookup(f->owner_id);
    // If it is accessed, set is as not accessed and move on
    if (pagedir_is_accessed(t->pagedir, f->frame_addr)) {
      pagedir_set_accessed(t->pagedir, f->frame_addr, false);
    } else {
      if (++f->unused_count > least_used) {
        eviction_candidate = f;
        least_used = f->unused_count;
      }
    }
  }
  eviction_candidate->unused_count = 0;

  return eviction_candidate;
}