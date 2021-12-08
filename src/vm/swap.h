#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <bitmap.h>
#include <stdbool.h>
#include "vm/page.h"

static struct bitmap* swap_table;
static struct block *swap_slot;

static void swap_init (void);
static bool swap_in (struct page *page);
static bool swap_out (struct page *page);

#endif /* vm/swap.h */