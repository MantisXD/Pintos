#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <bitmap.h>
#include <stdbool.h>
#include "vm/page.h"

static struct bitmap* swap_table;
static struct block *swap_slot;

void swap_init (void);
bool swap_in (struct page *page);
bool swap_out (struct page *page);

#endif /* vm/swap.h */