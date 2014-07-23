#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/off_t.h"
#include "filesys/directory.h"
#include "userprog/ring-buffer.h"

#define BAD_FD -1

#define THREAD_STATUS_OK            0      /* this thread is doing well */
#define THREAD_STATUS_WAITING       (1<<0) /* my parent is waiting on me */
#define THREAD_STATUS_DEAD          (1<<1) /* this thread has finished */
#define THREAD_STATUS_LOAD_FAILED   (1<<2) /* loading failed */
#define THREAD_STATUS_PARENT_DIED   (1<<3) /* the parent of this thread is dead, clean yourself up */

tid_t process_execute (const char *filename);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void process_init(void);

/* data structure for keeping vital process data */
/* File-descriptor overview:
  --------------------------
  Each process has a malloced dynamic array of file*'s to keep track
  of its open files. The file descriptor (or fd) for a given file* is
  just (index + 2), where "index" is the index of the file* in the
  array. The +2 offset is to account for the fact that fds 0 and 1 are
  reserved for stdin and stdout.

  When we refer to an index, we mean the absolute index in the array.
  When we refer to a fd, we mean the absolute index + 2.
*/

/* Data structure for keeping vital process data */
struct process
{
  tid_t main_tid;            /* My main thread tid (for process_wait) 
                                (Right now, only one thread per user process
                                is supported, so this is actually this
                                process's *only* tid) */
  char* command_line;        /* The command line used to create me */
  struct list children;      /* Children I have created */
  struct list_elem elem;     /* List element. */    
  struct thread* parent;     /* The parent thread */
  int exitcode;              /* The exit-code that this returns */
  int status;                /* Status flags. see top of this file. */
  
  struct file *exec_file;
  
  /* Fields dealing with my opened files */
  struct file **files;          /* Array of file*'s for my files */
  unsigned int allocated_size;  /* Max # of file*'s that I can hold
                                    without reallocating */
  unsigned int logical_size;    /* Number of file* slots that have
                                    been used at least once */
  struct ring_buffer unused_indices; /* Array of the indices within
                                        the "files" array that we aren't
                                        currently using. */

  /* Current working directory */
  struct dir *cwd;
};

void process_init(void); /* initialize process and lock stuff */
struct process* process_current(void); /* get the current running process */

/* Stores the given file* in the current process's files list, and
   returns the file descriptor for this file. */
int process_store_file(struct file *file);

/* Returns the file* for the given file-descriptor and current 
   process */
struct file *process_get_file(int fd);

/* Pops the file* corresponding to the given file-descriptor from
   the current processes' list. */
struct file *process_pop_file(int fd);

/* free the file lists, whenever you're done with them */
void process_free_file_lists(struct process *proc);

#endif /* userprog/process.h */
