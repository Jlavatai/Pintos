#include "vm/page.h"
#include <debug.h>

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