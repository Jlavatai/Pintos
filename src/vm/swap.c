#include "devices/block.h" // For swap block
#include "threads/synch.h" // For locks

static struct block *swap_block; // Swap Block Pointer
static size_t swap_size;         // Size of the Swap Block
static size_t max_pages;         // Number of pages that will fit into the SWAP block


void swap_init() {
	// Get the swap block from the filesystem
	swap_block = block_get_role (BLOCK_SWAP);
	if (swap_block == NULL) {
    	PANIC ("Swap Initialisation Failure: No SWAP Data Partition");
    }
    swap_size = block_size (swap_device) * BLOCK_SECTOR_SIZE; // block_size returns the number of sectors in a block
    max_pages = swap_size / PGSIZE
}

