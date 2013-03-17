#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>

enum page_status {
	PAGE_UNDEFINED = 0,
	PAGE_FILESYS,
	PAGE_SWAP,
	PAGE_MEMORY,
	PAGE_ZERO,
};

struct page_filesys_info {
	struct file *file;
	size_t offset;
};

struct page {
	struct hash_elem hash_elem;		/* Used to store the frame in the page table. */
	void *vaddr;	    			/* The address of the page in user virtual memory. */
	void *aux;						/* */
	enum page_status page_status;   /* Used to store the page's current status. */
};

unsigned supplemental_page_table_hash (const struct hash_elem *e,
									   void *aux);
bool supplemental_page_table_less (const struct hash_elem *a,
							  	   const struct hash_elem *b,
							  	   void *aux);

struct page * mmap_page_load(struct page * page);

#endif /* vm/page.h */