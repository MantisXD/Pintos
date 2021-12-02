#include "vm/frame.h"
#include "list.h"
#include "threads/synch.h"

static struct lock frame_lock;

static struct list frame_list;


void
frame_init ()
{
  lock_init (&frame_lock);
  list_init (&frame_list);
}

void *frame_allocate (enum palloc_flags flags)
{
  void *frame_page = palloc_get_page (PAL_USER | flags);\
  if (frame_page == NULL) {

  }
  else {
    struct frame *f = malloc(sizeof(struct frame));
    f->kva = frame_page;
    f->t = thread_current();

    lock_acquire (&frame_lock);
    list_push_back (&frame_list, &f->elem);
    lock_release (&frame_lock);
  }

  return frame_page;
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