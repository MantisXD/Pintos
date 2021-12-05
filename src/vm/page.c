#include <hash.h>
#include <stdio.h>
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include <bitmap.h>

static unsigned page_hash_func(const struct hash_elem *elem, void *aux);
static bool page_hash_less(const struct hash_elem *A, const struct hash_elem *B, void *aux);
static void page_hash_on_destroy (struct hash_elem *e, void *aux);

void
page_table_init (struct hash *spage_table)
{
  hash_init (spage_table, page_hash_func, page_hash_less, NULL);
}

void
page_table_destory (struct hash *spage_table)
{
  hash_destroy (spage_table, page_hash_on_destroy);
}

struct page *page_table_lookup (struct hash *spage_table, void *vaddr)
{
  struct page newPage;
  newPage.va = vaddr;

  struct hash_elem *e = hash_find (spage_table, &newPage.elem);
  if( e == NULL )
    return NULL;
  else
    return hash_entry(e, struct page, elem);
}
bool page_table_insert(struct hash *spage_table, struct page *page)
{
  struct hash_elem *e = hash_insert (spage_table, &page->elem);
  if( e == NULL)
    return true;
  else
    return false;
}
bool page_table_delete(struct hash *spage_table, struct page *page)
{
  struct hash_elem *e = hash_delete (spage_table, &page->elem);
  if( e != NULL )
    return true;
  else
    return false;
}

bool page_load_page (struct hash *spage_table, uint32_t *pd, void *upage)
{
  struct page *tPage = page_table_lookup (spage_table, upage);

  if( tPage == NULL )
    return false;

  if( tPage->kva != NULL )
    return false;

  void *kpage = frame_allocate(PAL_USER);
  if( kpage == NULL )
    return false;

  /*
  if (bitmap_test(swap_table, tPage->sector) == true) {
        swap_in(tPage);
  }
  */

  file_seek (tPage->file, tPage->ofs);
  if (tPage->read_bytes > 0 || tPage->zero_bytes > 0) {
    if (file_read (tPage->file, kpage, tPage->read_bytes) != (int) tPage->read_bytes) {
      frame_free (kpage);
      return false;
    }
    memset (kpage + tPage->read_bytes, 0, tPage->zero_bytes);

    if( !pagedir_set_page (pd, upage, kpage, tPage->writable))
    {
      frame_free (kpage);
      return false;
    }
  }

  tPage->kva = kpage;
//  printf ("page_load_page tPage->va: %p\n", tPage->va);
//  printf ("page_load_page tPage->writable: %d\n", tPage->writable);
  
  
  return true;
}

static unsigned
page_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
  struct page *page = hash_entry(e, struct page, elem);
  return hash_int((int)page->va);
}

static bool
page_hash_less(const struct hash_elem *A, const struct hash_elem *B, void *aux UNUSED)
{
  struct page *aPage = hash_entry(A, struct page, elem);
  struct page *bPage = hash_entry(B, struct page, elem);
  return aPage->va < bPage->va;
}

static void
page_hash_on_destroy (struct hash_elem *e, void *aux UNUSED)
{

}