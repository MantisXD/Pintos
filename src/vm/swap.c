#include "threads/vaddr.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include "devices/block.h"
#include "devices/partition.h"

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE);

void swap_init () {
    swap_slot = block_get_role(BLOCK_SWAP);
    swap_table = bitmap_create (block_size(swap_slot) / SECTORS_PER_PAGE);
}

void swap_in (struct page * page) {
    
}

bool swap_out (struct page *page) {

}