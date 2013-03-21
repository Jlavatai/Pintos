#include "vm/page.h"
#include <debug.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "vm/frame.h"

static struct page *supplemental_get_page_info (struct hash *supplemental_page_table,
                                                void *vaddr);
static void free_user_page(void* upage);
  
void
supplemental_insert_page_info (struct hash *supplemental_page_table,
                               struct page *page)
{
  hash_insert (supplemental_page_table, &page->hash_elem);
}

static struct page *
supplemental_get_page_info (struct hash *supplemental_page_table, void *vaddr)
{
  struct page p;
  p.vaddr = pg_round_down (vaddr);

  struct hash_elem *e = hash_find (supplemental_page_table, &p.hash_elem);
  if (e == NULL)
    return NULL;

  return hash_entry (e, struct page, hash_elem);
}

struct page*
supplemental_create_filesys_page_info (void *vaddr,
                                       struct page_filesys_info *filesys_info)
{
  struct page *page_info = malloc (sizeof (struct page));
  if (page_info) {
    page_info->page_status = PAGE_FILESYS;  
    page_info->aux = filesys_info;
    page_info->writable = false;
    page_info->vaddr = vaddr;
  }
  return page_info;
}

struct page*
supplemental_create_mmap_page_info (void *vaddr,
                                    struct page_mmap_info *mmap_info)
{
  struct page *page_info = malloc (sizeof (struct page));
  if (page_info)
  { 
    page_info->page_status = PAGE_MEMORY_MAPPED;
    page_info->aux = mmap_info;
    page_info->vaddr = vaddr;
  }
  return page_info;
}

struct page*
supplemental_create_zero_page_info (void *vaddr)
{
  struct page *page_info = malloc (sizeof (struct page));
  if (page_info) {
    page_info->page_status = PAGE_ZERO;
    page_info->aux = NULL;
    page_info->writable = true;
    page_info->vaddr = vaddr;
  }
  return page_info;
}

struct page*
supplemental_create_swap_page (void *vaddr,
                               struct swap_entry *swap_page)
{
  struct page *page_info = malloc (sizeof (struct page));
  if (page_info) {
    page_info->page_status = PAGE_SWAP;
    page_info->aux = (void*)swap_page;
    page_info->writable = false;
    page_info->vaddr = vaddr;
  }
  return page_info;
}

struct page*  
supplemental_create_in_memory_page_info (void *vaddr, bool writable)
{
  struct page *page_info = malloc (sizeof (struct page));
  if (page_info) {
    page_info->page_status = PAGE_IN_MEMORY;
    page_info->aux = NULL;
    page_info->writable = writable;
    page_info->vaddr = vaddr;
  }
  return page_info;
}


static void 
free_user_page(void* upage)
{
    struct thread *t = thread_current();
    void* kpage = pagedir_get_page(&t->pagedir, upage);
    if (kpage)
      frame_allocator_free_user_page(kpage, false);
}

void
supplemental_mark_page_in_memory (struct hash *supplemental_page_table, void *uaddr)
{
    struct page *p = supplemental_get_page_info (supplemental_page_table, uaddr);
    if (!p)
      PANIC ("Can't mark page %p as in-memory, because it is not in use.", p);

    p->page_status |= PAGE_IN_MEMORY;
}

void
supplemental_mark_page_not_in_memory (struct hash *supplemental_page_table, void *uaddr)
{
    struct page *p = supplemental_get_page_info (supplemental_page_table, uaddr);
    if (!p)
      PANIC ("Can't mark page %p as not-in-memory, because it is not in use.", p);

    p->page_status &= ~PAGE_IN_MEMORY;  
}

bool 
supplemental_entry_exists (struct hash *supplemental_page_table,
                           void *uaddr,
                           struct page **entry)
{
  struct page *p = supplemental_get_page_info (supplemental_page_table, uaddr);
  if (!p)
    return false;

  if (entry)
    *entry = p;

  return true;
}

void
supplemental_remove_page_entry (struct hash *supplemental_page_table, void *uaddr)
{
  struct page p;
  p.vaddr = pg_round_down (uaddr);

  struct page *page_info = NULL;
  if (!supplemental_entry_exists (supplemental_page_table, uaddr, &page_info))
    return;

  hash_delete (supplemental_page_table, &p.hash_elem);
  free (page_info);
}

bool 
supplemental_is_page_writable (struct hash *supplemental_page_table, void *uaddr)
{
  struct page *p = supplemental_get_page_info (supplemental_page_table, uaddr);
  if (!p)
    PANIC ("Could not determine if page %p is writable, as it is not mapped.", p);

  return p->writable; 
}

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
  struct page *page =  hash_entry (e, struct page, hash_elem);
  printf ("free\n");

  if (page->page_status & PAGE_FILESYS) {
    printf ("free filesys\n");

    if (page->aux)
      free(page->aux), page->aux = NULL;
  }

  if (page->page_status & PAGE_MEMORY_MAPPED) {
    printf ("free mem_mapped\n");
      if(page->aux)
        free (page->aux), page->aux = NULL;
  }
  if (page->page_status & PAGE_SWAP) {
    printf ("free swap\n");
      if (page->aux) {
        swap_free (page->aux);
      }
  }
  if (page->page_status & PAGE_IN_MEMORY) {
    printf ("free page in memory: %X\n", page->vaddr);
    if (page->vaddr) 
      free_user_page   (page->vaddr);
  }


  free (page);
}
