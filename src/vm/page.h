#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>

struct page {
	struct hash_elem hash_elem;		/* Used to store the frame in the page table. */
	size_t page_index;
};

#endif /* vm/page.h */