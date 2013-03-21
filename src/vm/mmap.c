#include "vm/mmap.h"

unsigned
mmap_hash (const struct hash_elem *e, void *aux UNUSED)
{
  const struct mmap_mapping *mapping = hash_entry (e, struct mmap_mapping, hash_elem);
  return hash_bytes (&mapping->mapid, sizeof (mapping->mapid));
}

bool
mmap_less (const struct hash_elem *a,
           const struct hash_elem *b,
           void *aux UNUSED)
{
  const struct mmap_mapping *mapping_a = hash_entry (a, struct mmap_mapping, hash_elem);
  const struct mmap_mapping *mapping_b = hash_entry (b, struct mmap_mapping, hash_elem);

  return mapping_a->mapid < mapping_b->mapid;
}

void
mmap_table_destroy_func (struct hash_elem *e, void *aux)
{
  struct mmap_mapping *mapping =  hash_entry (e,
                                              struct mmap_mapping,
                                              hash_elem);

  ASSERT (mapping->file != NULL);
  munmap_syscall_with_mapping (mapping, false);
}

void
mmap_write_back_data (struct mmap_mapping *mapping, void *source, size_t offset, size_t length)
{
  start_file_system_access ();
  file_seek (mapping->file, offset);
  file_write (mapping->file, source, length);
  end_file_system_access ();
}