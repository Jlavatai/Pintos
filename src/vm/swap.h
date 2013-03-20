#ifdef VM_SWAP_H

void swap_init();
void swap_save(void *page_pointer);
void swap_load(void *page_pointer);
void swap_delete(void *page_pointer);

#endif VM_SWAP_H