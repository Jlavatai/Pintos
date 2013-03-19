#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "threads/thread.h"
#include "lib/user/syscall.h"

enum page_status {
	PAGE_UNDEFINED = 0,
	PAGE_FILESYS,
	PAGE_SWAP,
	PAGE_MEMORY_MAPPED,
	PAGE_IN_MEMORY,
	PAGE_ZERO,
};

struct page_filesys_info {
	struct file *file;
	size_t offset;
};

struct page_mmap_info {
	mapid_t mapping;				/* The mmap() mapid. */
	size_t offset;					/* The offset into the file. */
	size_t length;					/* The number of bytes of the file stored in this page. */
};

struct page {
	struct hash_elem hash_elem;		/* Used to store the frame in the page table. */
	void *vaddr;	    			/* The address of the page in user virtual memory. */
	void *aux;						/* */
	enum page_status page_status;   /* Used to store the page's current status. */
	bool writable;					/* Stores if a page is writable or not */
};

void insert_filesys_page_info (struct hash *supplemental_page_table,
							   void *vaddr,
							   struct page_filesys_info *filesys_info);
void insert_zero_page_info (struct hash *supplemental_page_table,
					   		void *vaddr);
void insert_mmap_page_info (struct hash *supplemental_page_table,
					   		void *vaddr,
					   		struct page_mmap_info *mmap_info);

void stack_grow (struct thread * t, void * fault_ptr);

unsigned supplemental_page_table_hash (const struct hash_elem *e,
									   void *aux);
bool supplemental_page_table_less (const struct hash_elem *a,
							  	   const struct hash_elem *b,
							  	   void *aux);
void supplemental_page_table_destroy_func (struct hash_elem *e, void *aux);

struct page * mmap_page_load(struct page * page);

#endif /* vm/page.h */