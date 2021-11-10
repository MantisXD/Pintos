#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "filesys/file.h"
#include "filesys/directory.h"
#include "lib/kernel/list.h"

typedef int pid_t;

struct fd
{
    int fd;
    struct list_elem elem;
    struct file *file;
    struct dir *dir;
};

void syscall_init (void);

bool is_valid_addr (void *addr);

void check_mem (void *addr, size_t size);
/* System Call Functions */

/* A.	User Process Manipulation */
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
/* B.	File Manipulation */
int create (const char *file, unsigned initial_size);
int remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

#endif /* userprog/syscall.h */
