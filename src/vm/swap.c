#include "threads/vaddr.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include "devices/block.h"
#include "devices/partition.h"
#include "userprog/syscall.h"

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

void swap_init () {
    swap_slot = block_get_role(BLOCK_SWAP);
    if (swap_slot == NULL) {
        swap_table = bitmap_create (0);
        return;
    }
    swap_table = bitmap_create (block_size(swap_slot) / SECTORS_PER_PAGE);
}

bool swap_in (struct page * page) {
    size_t idx = page->sector;
    int i;

    if (bitmap_size(swap_table) == 0) {
        return false;
    }

    if (bitmap_test(swap_table, idx) == false) {
        return false;
    }

    for (i = 0; i < SECTORS_PER_PAGE; i++) {
        block_read (swap_slot, idx * SECTORS_PER_PAGE + i, page->kva + i * BLOCK_SECTOR_SIZE);
    }
    bitmap_set(swap_table, idx, false);

    return true;
}

bool swap_out (struct page *page) {
    size_t idx;
    int i;

    if (bitmap_size(swap_table) == 0) {
        return false;
    }

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