#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "threads/palloc.h"
#include <list.h>

struct frame{
  void *kva;
  struct thread *t;

  struct list_elem elem;
};

void frame_init (void);
void *frame_allocate (enum palloc_flags flags);
void frame_free (void *page);
struct frame *frame_find(void *page);

#endif /* vm/frame.h */