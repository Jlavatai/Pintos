#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>

struct page {
	struct hash_elem hash_elem;		/* Used to store the frame in the page table. */
	void *user_vaddr;				/* The address of the page in user virtual memory. */
};

#endif /* vm/page.h */