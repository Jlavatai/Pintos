#include "vm/frame.h"

#include <debug.h>

#include "threads/synch.h"
#include "threads/vaddr.h"


void frame_map(void * frame_addr, void *vaddr, bool writable);
void frame_unmap(void *frame_addr);

static unsigned frame_hash(const struct hash_elem *e, void *aux);
static bool frame_less (const struct hash_elem *a,
						const struct hash_elem *b,
						void *aux);

struct lock frame_table_lock;

/* Initialises the frame table. */
void
frame_table_init(void)
{
	hash_init (&frame_table, frame_hash, frame_less, NULL);
	lock_init (&frame_table_lock);
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
	void *kernel_vaddr = palloc_get_page (PAL_USER | flags);
	if (kernel_vaddr == NULL) {
		PANIC("No more user frames available.");
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

	return kernel_vaddr;
}

void
frame_allocator_free_user_page(void *kernel_vaddr)
{
	palloc_free_page (kernel_vaddr);
	frame_unmap (kernel_vaddr);
}