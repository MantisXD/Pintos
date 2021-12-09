#include <stdio.h>
#include "vm/frame.h"
#include "list.h"
#include <hash.h>
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include "vm/page.h"
#include "vm/swap.h"

static struct lock frame_lock;
static struct list frame_list;
struct frame* FIFO();
struct page* find_page(struct frame* f);

void
frame_init ()
{
  lock_init (&frame_lock);
  list_init (&frame_list);
}

void *frame_allocate (enum palloc_flags flags)
{
  void *frame_page = palloc_get_page (PAL_USER | flags);
  /*
  if (frame_page == NULL) {
    if(frame_evict()) {
      frame_page = palloc_get_page (PAL_USER | flags);
    }
    else {
      kill_process();
    }
  }
  */

  struct frame *f = malloc(sizeof(struct frame));
  f->kva = frame_page;
  f->t = thread_current();

  lock_acquire (&frame_lock);
  list_push_back (&frame_list, &f->elem);
  lock_release (&frame_lock);

  return frame_page;
}

struct frame* FIFO() {
  return list_entry(list_front(&frame_list), struct frame, elem);
}

struct page* find_page(struct frame* f) {
  struct thread* t = f->t;
  struct page *p;
  struct hash spt = t->spage_table;
  struct hash_iterator i;

  hash_first (&i, &spt);
  while (hash_next (&i))
    {
      p = hash_entry (hash_cur (&i), struct page, elem);
      if(p->kva == f->kva) return p;
    }
  return NULL;
}

bool frame_evict() {
  bool result;;
	struct frame* victim = FIFO();
  struct page* p = find_page(victim);

  if (p == NULL) kill_process();

  result = swap_out(p);
  if (result) {
    frame_free (p->kva);
    pagedir_clear_page (victim->t->pagedir, p->va);
    hash_delete (&victim->t->spage_table, &p->elem);
    free (p);
  }

	return result;
}

void
frame_free (void *page)
{
    struct frame *f = frame_find(page);

  lock_acquire (&frame_lock);
  if (f != NULL) {
    list_remove (&f->elem);
    palloc_free_page (f->kva);
  }
  lock_release (&frame_lock);
}

struct frame *
frame_find( void *page )
{
  struct list_elem *e;

  for (e = list_begin (&frame_list); e != list_end (&frame_list); e = list_next (e)) {
    struct frame *f = list_entry (e, struct frame, elem);
    if (f->kva == page) {
      return f;
    }
  }
  return NULL;
}