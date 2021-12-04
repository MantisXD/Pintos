#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <bitmap.h>

struct bitmap* swap_table;
void swap_init (void);
void swap_in (struct page *);
bool swap_out (struct page *);
#endif /* vm/swap.h */