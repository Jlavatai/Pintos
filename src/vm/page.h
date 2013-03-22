#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "threads/thread.h"
#include "lib/user/syscall.h"
#include "vm/swap.h"

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

enum page_status {
    PAGE_UNDEFINED = 0,             /* The default page status. */
    PAGE_FILESYS = 1 << 0,          /* Indicates a page containing data from an executable. */
    PAGE_SWAP  = 1 << 1,            /* Indicates a page stored in swap. */
    PAGE_MEMORY_MAPPED  = 1 << 2,   /* Indicates a page storing data for a memory-mapped file. */
    PAGE_IN_MEMORY = 1 << 3,        /* Indicates a page which is currently stored in memory. */
    PAGE_ZERO = 1 << 4,             /* Indicates a page initialised to zero. */
};

struct page_filesys_info {
    struct file *file;              /* The file pointer for the file the data is loaded from. */
    size_t offset;                  /* The file offset for the data in this page. */ 
    size_t length;                  /* The number of bytes from the file stored in this page. */
};

struct page_mmap_info {
    mapid_t mapid;                  /* The mmap() mapid. */
    size_t offset;                  /* The offset into the file. */
    size_t length;                  /* The number of bytes of the file stored in this page. */
};

struct page {
    struct hash_elem hash_elem;     /* Used to store the frame in the page table. */
    void *vaddr;                    /* The address of the page in user virtual memory. */
    void *aux;                      /* */
    enum page_status page_status;   /* Used to store the page's current status. */
    bool writable;                  /* Stores if a page is writable or not */
    struct lock lock;               /* Prevents race conditions. */
};

struct page* supplemental_create_filesys_page_info (void *vaddr,
                                                    struct page_filesys_info *filesys_info,
                                                    bool writable);
struct page* supplemental_create_zero_page_info (void *vaddr);
struct page* supplemental_create_in_memory_page_info (void *vaddr,
                                                      bool writable);
struct page* supplemental_create_mmap_page_info (void *vaddr,
                                                 struct page_mmap_info *mmap_info);
struct page* supplemental_create_swap_page (void *vaddr,
                                    struct swap_entry *swap_page);


void supplemental_insert_page_info (struct hash *supplemental_page_table,
                                    struct page *page);


void supplemental_mark_page_in_memory (struct hash *supplemental_page_table, void *uaddr);
void supplemental_mark_page_not_in_memory (struct hash *supplemental_page_table, void *uaddr);


bool supplemental_entry_exists (struct hash *supplemental_page_table,
                                void *uaddr,
                                struct page **entry);
bool supplemental_is_page_writable (struct hash *supplemental_page_table, void *uaddr);
void supplemental_remove_page_entry (struct hash *supplemental_page_table, void *uaddr); 


/* Supplemental page table hash functions */
unsigned supplemental_page_table_hash (const struct hash_elem *e,
                                       void *aux);
bool supplemental_page_table_less (const struct hash_elem *a,
                                   const struct hash_elem *b,
                                   void *aux);
void supplemental_page_table_destroy_func (struct hash_elem *e, void *aux);

void print_page_info ();
#endif /* vm/page.h */