#include "vm/page.h"
#include <debug.h>
#include "threads/palloc.h"
#include "threads/vaddr.h"


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

void
stack_grow (struct thread * t, void * fault_ptr) {
    // Get the user page of fault_addr
    void * new_page_virtual = pg_round_down (fault_ptr);
    ASSERT(is_user_vaddr(fault_ptr));
    // Allocate a new frame
    void * page_ptr_frame = frame_allocator_get_user_page(new_page_virtual, PAL_ZERO, true);
    if (page_ptr_frame == NULL)
    {
        PANIC("Stack Grow Fault");
    }
}