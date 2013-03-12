#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>

struct frame {
	struct hash_elem hash_elem;		/* Used to store the frame in the frame table. */
	int32_t frame_addr;				/* The address of the frame in memory. */
	struct page *page;				/* Stores the page mapped into this frame */
};

#endif /* vm/frame.h */