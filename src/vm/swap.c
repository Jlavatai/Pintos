
#include "vm/swap.h"

#include "devices/block.h" // For swap block
#include "threads/synch.h" // For locks
#include "threads/vaddr.h" // For PGSIZE

#define PAGE_SECTORS PG_SIZE / BLOCK_SECTOR_SIZE // each read and write call returns a sector.

static struct block *swap_block; // Swap Block Pointer
static size_t swap_size;         // Size of the Swap Block in bytes
static size_t max_pages;         // Number of pages that will fit into the SWAP block

static struct lock swap_lock;        // Global lock to stop concurrent access. TODO lock per page.

static struct swap_entry *swap_table;
static size_t swap_table_size;


struct swap_entry *find_first_free_entry(); // Utility Function for finding a free swap page

void swap_init() {
  // Get the swap block from the filesystem
  swap_block = block_get_role (BLOCK_SWAP);
  if (swap_block == NULL) {
    PANIC ("Swap Initialisation Failure: No Swap Data Partition");
  }
  // block_size returns the number of sectors in a block
  swap_size = block_size (swap_block) * BLOCK_SECTOR_SIZE; 
  max_pages = swap_size / PGSIZE;
  // For each page, allocate some memory
  swap_table_size = max_pages * sizeof(struct swap_entry);
  swap_table = malloc(swap_table_size);
  if (!swap_table) {
    PANIC ("Swap Initialisation Failure: Failed to initialise the Swap Table");
  }
  lock_init(&swap_lock);
}

// Called at the end of the OS lifetime, to cleanup the memory used
void swap_destroy() {
  free(swap_table);
} 

// Allocate a page in Swap, returning the page address.
struct swap_entry *swap_alloc() {
  lock_acquire(&swap_lock);
  struct swap_entry* entry = find_first_free_entry();

  if (!entry)
    PANIC("No more SWAP available");

  entry->in_use = true;
  lock_release(&swap_lock);
  return entry;

}

// Returns the first free entry, or NULL if none available.
struct swap_entry *find_first_free_entry() {
  struct swap_entry * entry;
  for (entry = swap_table; entry < swap_table + swap_table_size; entry++) {
    if (!entry -> in_use)
      return entry;
  }
  return NULL;
}
// Free a given page in Swap
void  swap_free(struct swap_entry * swap_location) {
  lock_acquire(&swap_lock);
  swap_location->in_use = false;
  lock_release(&swap_lock);
}


// Save a page to Swap
void  swap_save(struct swap_entry * swap_location, void *physical_address) {
  ASSERT(swap_location->in_use);
} 

// Load a page from swap, and return it's physical address, or NULL if there are no more pages available.
void *swap_load(struct swap_entry * swap_location) {
  ASSERT(swap_location->in_use);
}
