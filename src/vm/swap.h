#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <stdbool.h>

struct swap_entry {
	void *block_location;
	bool in_use;
};


void swap_init(); // Called to initialise the Swap System by init.c
void swap_destroy(); // Called at the end of the OS lifetime, to cleanup the memory used
struct swap_entry *swap_alloc(); // Allocate a page in Swap, returning the page address.
void  swap_free(struct swap_entry * swap_location); // Free a given page in Swap
void  swap_save(struct swap_entry * swap_location, void *physical_address); // Save a page to Swap
void *swap_load(struct swap_entry * swap_location); // Load a page from swap, and return it's physical address, or NULL if there are no more pages available.

#endif VM_SWAP_H