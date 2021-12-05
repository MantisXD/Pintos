#ifndef VM_PAGE_H
#define VM_PAGE_H
#include "filesys/file.h"
#include <hash.h>
#include "devices/block.h"

struct page {
  void *va;
  void *kva;

  struct file *file;
  off_t ofs;
  uint32_t read_bytes;
  uint32_t zero_bytes;
  bool writable;
  block_sector_t sector;

  struct hash_elem elem;
};

void page_table_init (struct hash *spage_table);
void page_table_destory(struct hash *spage_table);
struct page *page_table_lookup (struct hash *spage_table, void *vaddr);
bool page_table_insert(struct hash *spage_table, struct page *page);
bool page_table_delete(struct hash *spage_table, struct page *page);

bool page_load_page(struct hash *spage_table, uint32_t *pd, void *upage);
#endif /* vm/page.h */