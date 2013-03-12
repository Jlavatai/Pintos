#include "vm/frame.h"

#include <debug.h>

struct hash frame_table;

static unsigned frame_hash(const struct hash_elem *e, void *aux);
static bool frame_less (const struct hash_elem *a,
						const struct hash_elem *b,
						void *aux);

/* Initialises the frame table. */
void
frame_init(void)
{
	hash_init (&frame_table, frame_hash, frame_less, NULL);
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