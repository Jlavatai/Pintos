#ifndef VM_MMAP_H
#define VM_MMAP_H

#include <hash.h>
#include <debug.h>

typedef int mapid_t;

struct mmap_mapping {
  struct hash_elem hash_elem;
  mapid_t mapid;                          /* The memory map identifier. */
  struct file *file;                      /* The file being mapped into memory. */
  void *uaddr;                            /* The user virtual address that the file is mapped to. */
};

unsigned mmap_hash (const struct hash_elem *e, void *aux UNUSED);
bool mmap_less (const struct hash_elem *a,
                const struct hash_elem *b,
                void *aux UNUSED);
void mmap_table_destroy_func (struct hash_elem *e, void *aux);
void mmap_write_back_data (struct mmap_mapping *mapping,
						   void *source,
						   size_t offset,
						   size_t length);

#endif VM_MMAP_H