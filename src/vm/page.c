#include "vm/page.h"
#include <debug.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"


static void supplemental_insert_page_info (struct hash *supplemental_page_table,
                                           void *vaddr, struct page *page);
static struct page *supplemental_get_page_info (struct hash *supplemental_page_table,
                                                void *vaddr);

unsigned
supplemental_page_table_hash (const struct hash_elem *e, void *aux UNUSED)
{
  const struct page *p = hash_entry (e, struct page, hash_elem);

  return hash_bytes (&p->vaddr, sizeof(p->vaddr));
}

bool
supplemental_page_table_less (const struct hash_elem *a,
                const struct hash_elem *b,
                void *aux UNUSED)
{
  const struct page *page_a = hash_entry (a, struct page, hash_elem);
  const struct page *page_b = hash_entry (b, struct page, hash_elem);

  return page_a->vaddr < page_b->vaddr;
}

void
supplemental_page_table_destroy_func (struct hash_elem *e, void *aux UNUSED)
{
  struct page *page =  hash_entry (e,
            struct page,
            hash_elem);

  switch(page->page_status){
  case PAGE_FILESYS:
    free(page->aux);
    break;
  case PAGE_SWAP:
    break;
  case PAGE_IN_MEMORY:
    break;
  case PAGE_ZERO:
    break;
  case PAGE_MEMORY_MAPPED:
    break;
  default:
    break;
  }

}

static void
supplemental_insert_page_info (struct hash *supplemental_page_table,
                               void *vaddr, struct page *page)
{
  page->vaddr = vaddr;
  hash_insert (supplemental_page_table, &page->hash_elem);
}

static struct page *
supplemental_get_page_info (struct hash *supplemental_page_table, void *vaddr)
{
  struct page p;
  p.vaddr = vaddr;

  struct hash_elem *e = hash_find (supplemental_page_table, &p.hash_elem);
  if (e == NULL)
    return NULL;

  return hash_entry (e, struct page, hash_elem);
}

void
supplemental_insert_filesys_page_info (struct hash *supplemental_page_table,
                          void *vaddr,
                          struct page_filesys_info *filesys_info)
{
  struct page *page_info = malloc (sizeof (struct page));
  page_info->page_status = PAGE_FILESYS;  
  page_info->aux = filesys_info;
  page_info->writable = false;

  supplemental_insert_page_info (supplemental_page_table, vaddr, page_info);
}

void
supplemental_insert_mmap_page_info (struct hash *supplemental_page_table,
                       void *vaddr,
                       struct page_mmap_info *mmap_info)
{
  struct page *page_info = malloc (sizeof (struct page));
  page_info->page_status = PAGE_MEMORY_MAPPED;
  page_info->aux = mmap_info;

  supplemental_insert_page_info (supplemental_page_table, vaddr, page_info);
}

void
supplemental_insert_zero_page_info (struct hash *supplemental_page_table,
                                    void *vaddr)
{
  struct page *page_info = malloc (sizeof (struct page));
  page_info->page_status = PAGE_ZERO;
  page_info->aux = NULL;
  page_info->writable = true;

  supplemental_insert_page_info (supplemental_page_table, vaddr, page_info);
}

void
supplemental_insert_in_memory_page_info (struct hash *supplemental_page_table,
                                         void *vaddr, bool writable)
{
  struct page *page_info = malloc (sizeof (struct page));
  page_info->page_status = PAGE_IN_MEMORY;
  page_info->aux = NULL;
  page_info->writable = writable;

  supplemental_insert_page_info (supplemental_page_table, vaddr, page_info);
}

void
supplemental_mark_page_in_memory (struct hash *supplemental_page_table, void *uaddr)
{
    struct page p;
    p.vaddr = uaddr;

    struct hash_elem *e = hash_find (supplemental_page_table, &p.hash_elem);
    struct page *page = hash_entry (e, struct page, hash_elem);

    page->page_status |= PAGE_IN_MEMORY;
}

bool 
supplemental_entry_exists (struct hash *supplemental_page_table, void *uaddr)
{
  struct page p;
  p.vaddr = pg_round_down(uaddr);

  return hash_find(supplemental_page_table, &p.hash_elem);
}

bool 
supplemental_is_page_writable (struct hash *supplemental_page_table, void *uaddr) {
  struct page p;
  p.vaddr = pg_round_down(uaddr);

  struct hash_elem *e = hash_find(supplemental_page_table, &p.hash_elem);
  if (!e)
    return false;

  struct page *page = hash_entry(e, struct page, hash_elem);

  return page->writable; 
}