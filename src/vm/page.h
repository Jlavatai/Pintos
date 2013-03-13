#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>

struct page {
	struct hash_elem hash_elem;		/* Used to store the frame in the page table. */
	void *user_vaddr;				/* The address of the page in user virtual memory. */
};

unsigned supplemental_page_table_hash (const struct hash_elem *e,
									   void *aux);
bool supplemental_page_table_less (const struct hash_elem *a,
							  	   const struct hash_elem *b,
							  	   void *aux);

#endif /* vm/page.h */