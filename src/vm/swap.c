#include "threads/vaddr.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include "devices/block.h"
#include "devices/partition.h"

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

static void swap_init () {
    swap_slot = block_get_role(BLOCK_SWAP);
    swap_table = bitmap_create (block_size(swap_slot) / SECTORS_PER_PAGE);
}

static bool swap_in (struct page * page) {
    size_t idx = page->sector;
    int i;

    if (bitmap_test(swap_table, idx) == false) {
        return false;
    }

    for (i = 0; i < SECTORS_PER_PAGE; i++) {
        block_read (swap_slot, idx * SECTORS_PER_PAGE + i, page->kva + i * BLOCK_SECTOR_SIZE);
    }
    bitmap_set(swap_table, idx, false);

    return true;
}

static bool swap_out (struct page *page) {
    size_t idx;
    int i;

    idx = bitmap_scan_and_flip (swap_table, 0, 1, false);
    if (idx == BITMAP_ERROR)
        return false;

    for (i = 0; i < SECTORS_PER_PAGE; i++){
        block_write (swap_slot, idx * SECTORS_PER_PAGE + i, page->kva + i * BLOCK_SECTOR_SIZE);
    }

    page->sector = idx;
    page->file = NULL;

    return true;
}