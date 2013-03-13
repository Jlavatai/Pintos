#ifndef VM_FRAME_H
#define VM_FRAME_H
#include <hash.h>
#include "vm/page.h"

struct hash frame_table;

struct frame {
	struct hash_elem hash_elem;		/* Used to store the frame in the frame table. */
	int32_t frame_addr;				/* The address of the frame in memory. */
	struct page *page;				/* Stores the page mapped into this frame */
};

void frame_table_init(void);
void frame_map(void * frame_addr, size_t page_index);

void *frame_allocator_get_user_frame(void);

#endif /* vm/frame.h */