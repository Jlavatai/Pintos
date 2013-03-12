#include "vm/frame.h"

#include <debug.h>


static unsigned frame_hash(const struct hash_elem *e, void *aux);
static bool frame_less (const struct hash_elem *a,
						const struct hash_elem *b,
						void *aux);

/* Initialises the frame table. */
void
frame_table_init(void)
{
	hash_init (&frame_table, frame_hash, frame_less, NULL);
}

void frame_map(void * frame_addr, size_t page_index)
{	
	struct page *new_page = NULL;
	new_page = malloc (sizeof(struct frame));
	if(new_page == NULL) 
	{
		PANIC("Failed to malloc memory for struct page");
	}

	new_page->page_index = page_index;

	struct frame *new_fr = NULL;
	new_fr = malloc (sizeof(struct frame));
	if(new_fr == NULL) 
	{
		PANIC("Failed to malloc memory for struct frame");
	}

	new_fr->page = new_page;
	new_fr->frame_addr = frame_addr;

	hash_insert(&frame_table, &new_fr->hash_elem);
}


/* Hash function for the frame table. */
static unsigned
frame_hash(const struct hash_elem *e, void *aux UNUSED)
{
	const struct frame *f = hash_entry (e, struct frame, hash_elem);

	return hash_bytes (&f->frame_addr, sizeof (f->frame_addr));
}

static bool
frame_less (const struct hash_elem *a, const struct hash_elem *b,
			void *aux UNUSED)
{
	const struct frame *frame_a = hash_entry (a, struct frame, hash_elem);
	const struct frame *frame_b = hash_entry (b, struct frame, hash_elem);

	return frame_a->frame_addr < frame_b->frame_addr;
}