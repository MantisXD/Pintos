#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/exception.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "filesys/off_t.h"
#include "lib/kernel/list.h"
#include "filesys/inode.h"

static void syscall_handler (struct intr_frame *);

/* User memory access */

static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
void user_memory_access(void* esp, size_t size, int32_t* arg);

/* File systems */

struct file* get_file(int fd);

struct lock file_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void 
halt (void)
{
  shutdown_power_off();
}

void
exit (int status)
{

  printf("%s: exit(%d)\n", thread_name(), status);
  thread_current()->exit_status=status;
  thread_exit();
}

pid_t 
exec (const char *cmd_line)
{
  if (cmd_line >= PHYS_BASE) 
  {
    return -1;
  }
  return (pid_t)process_execute(cmd_line);
}

int 
wait (pid_t pid)
{
  return process_wait((tid_t)pid);
}

int 
create (const char *file, unsigned initial_size)
{
  if (file >= PHYS_BASE) 
  {
    return -1;
  }

  int ret;
  lock_acquire(&file_lock);
  ret =  filesys_create(file, initial_size);
  lock_release (&file_lock);
  return ret;
}

int 
remove (const char *file)
{
  if (file >= PHYS_BASE) 
  {
    return -1;
  }

  int ret;
  lock_acquire(&file_lock);
  ret = filesys_remove(file);
  lock_release (&file_lock);
  return ret;
}

int 
open (const char *file)
{
  if (file >= PHYS_BASE) 
  {
    return -1;
  }

  int ret;
  lock_acquire(&file_lock);
  struct file* fp = filesys_open(file);
  // Fail to open the file.
  if (fp == NULL)
    ret = -1;
  else
  {
    struct thread *cur = thread_current();
    struct fd* fd = palloc_get_page(0);
    fd->fd = (int)list_size(&cur->fd_list) + 2;
    list_push_back(&cur->fd_list, &(fd->elem));
    fd->file = fp;
    fd->dir = dir_open(file_get_inode(fd->file));
    ret = fd->fd;
  }
  lock_release (&file_lock);
  return ret;
}

int 
filesize (int fd)
{
  int ret;
  lock_acquire(&file_lock);
  struct file *fp = get_file(fd);
  if (fp == NULL)
    ret = -1;
  else
    ret = file_length(fp);
  lock_release (&file_lock);
  return ret;
}

int 
read (int fd, void *buffer, unsigned size)
{
  if ((buffer + size - 1) >= PHYS_BASE) 
  {
    return -1;
  }

  int ret;
  lock_acquire(&file_lock);
  struct file *fp = get_file(fd);

  if (fp == NULL)
    ret = -1;
  else
  {
    if (fd == 0) // STDIN
    {
      unsigned i;
      for (i = 0; i < size; i++)
      {
        char temp = input_getc();
        put_user(buffer+i, temp);
        if (temp == '\0')
          break;
      }
      ret = (int)i;
    }
    else if (fd == 1) // STDOUT
      ret = -1;
    else
        ret = file_read(fp, buffer, size);
  }
  lock_release (&file_lock);
  return ret;
}

int 
write (int fd, const void *buffer, unsigned size)
{
  if ((buffer + size - 1) >= PHYS_BASE) 
  {
    return -1;
  }

  int ret;
  lock_acquire (&file_lock);
  struct file* fp = get_file(fd);
  if (fp == NULL)
    ret = -1;
  else
  {
    if (fd == 0) //STDIN
    ret = -1;
    else if (fd == 1) // STDOUT
    {
      puts(buffer);
      ret = (int)size;
    }
    else
      ret = file_write(fp, buffer, size);
  }
  lock_release (&file_lock);
  return ret;
}

void 
seek (int fd, unsigned position)
{
  lock_acquire (&file_lock);
  struct file *fp = get_file(fd);
  if (fp == NULL)
    return;
  else
    file_seek(fp, position);
  lock_release (&file_lock);
  return;
}

unsigned 
tell (int fd)
{
  unsigned ret;
  lock_acquire (&file_lock);
  struct file *fp = get_file(fd);
  if (fp == NULL)
    ret = -1;
  else
    ret = file_tell(fp);
  lock_release (&file_lock);
  return ret;
}

void 
close (int fd)
{
  lock_acquire (&file_lock);
  struct file *fp = get_file(fd);
  if (fp == NULL)
    return;
  else
    file_close(fp);
  lock_release (&file_lock);
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

void
user_memory_access(void* esp, size_t size, int32_t* arg)
{
  char* temp;
  size_t i;

  temp = malloc(size);
  for(i=0; i < size; i++) 
  {
    if (esp >= PHYS_BASE)
      exit(-1);
    temp[i] = get_user(esp + i);
  }
  *arg = atoi(temp);
  free(temp);
}

/* Return a file pointer with a given fd id by searching from fd_list of thread_current. */
struct file* 
get_file(int fd)
{
  struct thread* cur = thread_current();
  struct list *fd_list = &(cur->fd_list);
  struct list_elem *it;

  if (!list_empty(fd_list))
  {
      for(it=list_begin(fd_list); it != list_end(fd_list); it = list_next(it))
    {
      struct fd *fd = list_entry(it, struct fd, elem);
      if (fd->fd == fd)
        return fd->file;
    }
  }
  return NULL;
}

static void
syscall_handler (struct intr_frame *f) 
{
  printf("System Call");

  void* cur_esp = f->esp;
  int arg[4]; // Argument list for system calls.

  user_memory_access(cur_esp, sizeof(int), &arg[0]);
  printf("system call number: (%d)", arg[0]);

  switch ((int)arg[0])
	{
	  case SYS_HALT:
      printf("handling system call (halt)");
		  halt();
		  break;
	  case SYS_EXIT:
      printf("handling system call (exit)");
      user_memory_access(cur_esp + 4, sizeof(int), &arg[1]);
      printf("status: %d", arg[1]);
		  exit((int)arg[1]);
		  break;
    case SYS_EXEC:
      printf("handling system call (exec)");
      f->eax = exec((char*)arg[1]);
      break;
    case SYS_WAIT:
      printf("handling system call (wait)");
      user_memory_access(cur_esp + 4, sizeof(pid_t), &arg[1]);
      printf("pid: %d", arg[1]);
      f->eax = wait((pid_t)arg[1]);
      break;
    case SYS_CREATE:
      printf("handling system call (create)");
      f->eax = create((char*)arg[1], (unsigned int)arg[2]);
      break;
    case SYS_REMOVE:
      printf("handling system call (remove)");
      f->eax = remove((char*)arg[1]);
      break;
    case SYS_OPEN:
      printf("handling system call (open)");
      f->eax = open((char*)arg[1]);
      break;
    case SYS_FILESIZE:
      printf("handling system call (filesize)");
      f->eax = filesize((int)arg[1]);
      break;
    case SYS_READ:
      printf("handling system call (read)");
      f->eax = read((int)arg[1], (void*)arg[2], (unsigned int)arg[3]);
      break;
    case SYS_WRITE:
      printf("handling system call (write)");
      user_memory_access(cur_esp + 4, sizeof(int), &arg[1]);
      user_memory_access(cur_esp + 8, sizeof(void*), &arg[2]);
      user_memory_access(cur_esp + 12, sizeof(unsigned int), &arg[3]);
      printf("fd: %d, buffer: %d, size: %d", arg[1], arg[2], arg[3]);
      f->eax = write((int)arg[1], (void*)arg[2], (unsigned int)arg[3]);
      break;
    case SYS_SEEK:
      printf("handling system call (seek)");
      seek((int)arg[1], (unsigned int)arg[2]);
      break;
    case SYS_TELL:
      printf("handling system call (tell)");
      f->eax = tell((int)arg[1]);
      break;
    case SYS_CLOSE:
      printf("handling system call (close)");
      close((int)arg[1]);
      break;
    default:
      break;
	}
  thread_exit();
}
