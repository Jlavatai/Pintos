#ifndef VM_FRAME_H
#define VM_FRAME_H
#include <hash.h>
#include "vm/page.h"
#include "threads/palloc.h"

// Preprocessor Defs for testing
#define BYTETOBINARYPATTERN "%d%d%d%d%d%d%d%d"
#define BYTETOBINARY(byte)  \
  (byte & 0x80 ? 1 : 0), \
  (byte & 0x40 ? 1 : 0), \
  (byte & 0x20 ? 1 : 0), \
  (byte & 0x10 ? 1 : 0), \
  (byte & 0x08 ? 1 : 0), \
  (byte & 0x04 ? 1 : 0), \
  (byte & 0x02 ? 1 : 0), \
  (byte & 0x01 ? 1 : 0) 
// end preprocessor defs

struct hash frame_table;

struct frame {
	struct hash_elem hash_elem;		/* Used to store the frame in the frame table. */
	int32_t frame_addr;				/* The address of the frame in memory.         */
	struct page *page;				/* Stores the page mapped into this frame      */
	tid_t owner_id;						/* Stores the tid of the owning thread    */
	int32_t unused_count;
};

void frame_table_init(void);

void *frame_allocator_get_user_page(void *user_vaddr, enum palloc_flags flags, bool writable);
void *frame_allocator_get_user_page_multiple(void *user_vaddr,
											 unsigned int num_frames,
											 enum palloc_flags flags,
											 bool writable);
void frame_allocator_free_user_page(void *kernel_vaddr);



#endif /* vm/frame.h */