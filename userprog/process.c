#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "lib/stdio.h"
#include "filesys/cache.h"

/* Offset value for file-descriptors, to account for stdin and stdout */
#define FD_OFFSET            2 

/* Initial number of file*'s to allocate per-process in "files" and
   "unused_indices" arrays */
#define INITIAL_ARR_SIZE     2

/* Factor by which to increase the "files" and "unused_indices" arrays */ 
#define MEM_INCREASE_FACTOR  2 

/* Largest length we'll allow for a valid command string. */
#define MAX_CMDSTRING_LEN    (PGSIZE-2)

static thread_func execute_thread NO_RETURN;
static bool load (struct process* this_process, void (**eip) (void), void **esp);

/* the process of the initial thread. it's on the stack and not malloc'd */
static struct process initial_process;

/* this lock is for making sure certain parts of process_exit are atomic. */
struct lock process_exit_lock;

static int fd_to_index(int fd);
static int index_to_fd(int index);
static bool ensure_space_at_end(struct process *proc);
struct file *get_file_helper(struct process *proc, int index);

static tid_t process_execute_error(struct process* offending_process, bool remove_from_list);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *filename) 
{
  tid_t tid;
  struct process* child_process = 
    (struct process* )malloc(sizeof(struct process));
    
  /* malloc had a problem. return a failure to the user. */
  if(child_process == NULL)
    return TID_ERROR;
    
  /* Make a copy of FILENAME.
     Otherwise there's a race between the caller and load() 
     First, allocate space (and make sure it was allocated) */
  child_process->command_line = palloc_get_page (0);
  if (child_process->command_line == NULL)
  {
    free(child_process);
    return TID_ERROR;
  }  
  // Second, perform the copy (making sure the copy is smaller than PGSIZE)
  if (strlcpy (child_process->command_line, filename, PGSIZE) 
         > MAX_CMDSTRING_LEN)
  {
    return process_execute_error(child_process, false);
  }

  /* set up the child's process struct */
  child_process->status = THREAD_STATUS_OK; /* loading the thread! */
  
  /* specify the child's parent, and add the child to the children list */
  child_process->parent = thread_current(); 
  list_push_back(&process_current()->children, &child_process->elem);

  /* Child inherits parent's cwd */
  ASSERT(dir_reopen(process_current()->cwd, &child_process->cwd));
  
  /* Create a new thread to execute FILENAME. */
  tid = thread_create (filename, PRI_DEFAULT, execute_thread, child_process);
  if (tid == TID_ERROR)
    tid = process_execute_error(child_process, true);
  else
  {
      child_process->main_tid = tid;
      
      /* block until the child thread is done loading. there is no
       * race condition here because the child thread will wait
       * until we have started blocking */
      enum intr_level old_level = intr_disable ();
      thread_block();
      intr_set_level(old_level);
      
      /* the child is done loading, we can check */
      if(child_process->status & THREAD_STATUS_LOAD_FAILED)
          tid = process_execute_error(child_process, true);
  }
  
  return tid;
}

/* clean things up if a process fails in process_execute */
static tid_t process_execute_error(struct process* offending_process, bool remove_from_list)
{
    palloc_free_page(offending_process->command_line);
    if(remove_from_list)
        list_remove(&offending_process->elem);
    free(offending_process);
    return TID_ERROR;
}

/* A thread function that loads a user process and starts it
   running. */
static void
execute_thread (void *aux)
{
  struct process* this_process = (struct process*)aux;
  struct intr_frame if_;
  bool success;

  thread_current()->parent_process = this_process;
  
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (this_process, &if_.eip, &if_.esp);
  
  /* report to the parent whether the loading was success or fail */   
  
  while(true)
  {
    lock_acquire(&process_exit_lock);
    /* make sure the parent can't exit when we do this check */
    if(this_process->parent == NULL)
    {
        this_process->status |= THREAD_STATUS_PARENT_DIED;
        break;
    }        
    if(this_process->parent->status == THREAD_BLOCKED)
        break;
    lock_release(&process_exit_lock);

    /* if the child thread started executing before the parent
     * thread blocked, spin (see end of process_execute()) */
    thread_yield();
  }

  if(!success)
    this_process->status |= THREAD_STATUS_LOAD_FAILED; 
    /* we don't unblock parent in this case until this process
       actually exits (to ensure data structures are freed at the
       right time) */
  else if(!(this_process->status & THREAD_STATUS_PARENT_DIED))
  {
    /* the load worked, unblock */
    thread_unblock(this_process->parent); 
  }
  
  /* we release the lock all the way out here because we are
   * still reading from our status, and at this time the parent
   * could write to our status if it is exiting */
  lock_release(&process_exit_lock);

  /* If load failed, quit. */
  if (!success) 
    thread_exit ();
 
  /* set up the new process */
  list_init(&this_process->children);  
  /* set the starting exitcode to -1, so that if
     the kernel kills the process, it should exit with -1 */
  this_process->exitcode = -1; 
  this_process->files = 
    (struct file **)malloc(INITIAL_ARR_SIZE * sizeof(struct file*));
  this_process->allocated_size = INITIAL_ARR_SIZE;
  this_process->logical_size = 0;    
  this_process->unused_indices.buffer = 
    (int *)malloc(INITIAL_ARR_SIZE * sizeof(int*));
  rb_init_buff(&this_process->unused_indices, INITIAL_ARR_SIZE);
    
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm ("mov %%esp, %0; jmp intr_exit" :: "g" (&if_));
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
    struct process* this_process = process_current();
    struct process* child_process;
    int exitstatus;
    struct list_elem *e;
    enum intr_level old_level;
    
    /* we're going to iterate through all our children to
     * see if we find a matching tid */
    for (e = list_begin (&this_process->children); 
         e != list_end (&this_process->children); 
         e = list_next(e))
    {
        child_process = list_entry (e, struct process, elem);
        if(child_process->main_tid == child_tid)
        {
            old_level = intr_disable ();
            
            /* check if the child process hasn't already exited */
            if(!(child_process->status & THREAD_STATUS_DEAD))
            {                
                /* the child is still alive, we need to disable
                 * interrupts and start blocking */                
                
                child_process->status |= THREAD_STATUS_WAITING;
                thread_block();              
                intr_set_level(old_level);
            }
            else /* the thread is dead, we don't have to worry about sync probs */
                intr_set_level(old_level);
            
            /* if we have been waiting for this child, we are responsible for
             * freeing up its struct process. (see process_exit) */
            exitstatus = child_process->exitcode;
            list_remove(&child_process->elem);
            free(child_process);
            return exitstatus;
        }
    }

    /* we couldn't find this child, so fail */
    return TID_ERROR;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  if (is_cache_thread()) return;
  struct thread *cur = thread_current ();
  struct process* this_process = thread_current()->parent_process;
  uint32_t *pd;
  struct list_elem *e;
  struct process* child_process;    
      
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  /* the initial thread doesn't need to clean up anything since
   * it never opens any files and is not malloc'd. therefore,
   * only do the following if the thread isn't the initial one */
  if(this_process != NULL)   
  {            
      /* this process was a failure, no data structures were
       * initialized (therefore we don't need to clean them up)
       * just quit. no synchronization problems here because if
       * the load failed, parent is still sleeping. */
      if(this_process->status & THREAD_STATUS_LOAD_FAILED)
      {
        /* now we can unblock parent, after we've finished reading from this_process */
        if(this_process->status & THREAD_STATUS_PARENT_DIED) /* but my parent died abruptly */
            free(this_process);
        else
            thread_unblock(this_process->parent); 
        return;
      }

      unsigned int i=0;
      struct file *currfile = NULL;
    
      /* Close process file */
      file_close(this_process->exec_file); 
      
      for (i=0;i<this_process->logical_size;i++){
         currfile = this_process->files[i];
         if (currfile!=NULL)file_close(currfile);
      }
      
      /* free the fd lists */
      process_free_file_lists(this_process);
      
      /* print an exit message */
      printf ("%s: exit(%d)\n", this_process->command_line, 
              this_process->exitcode);
              
      palloc_free_page (this_process->command_line);
      
      /* we have to lock this section, or else bad interleaving
       * will cause a memory leak. */
       
      lock_acquire(&process_exit_lock);

      /* free up any dead children - we won't be waiting on them anymore.
       * also, notify live children that the parent is dead. */
      for (e = list_begin (&this_process->children); 
           e != list_end (&this_process->children); 
           e = list_next(e))
      {
          child_process = list_entry (e, struct process, elem);
          
          if(child_process->status & THREAD_STATUS_DEAD)
            free(child_process);
          else
            child_process->status |= THREAD_STATUS_PARENT_DIED;
      }
      
      /* if the parent is dead, the thread has to free its own process
       * struct. Otherwise, leave it up to the parent */      
      if(this_process->status & THREAD_STATUS_PARENT_DIED)
        free(this_process);
      else
      {      
          this_process->status |= THREAD_STATUS_DEAD;
          
          /* the waiter will free this process after it's gotten exit status */
          if(this_process->status & THREAD_STATUS_WAITING) 
            thread_unblock(this_process->parent);
      }
      
      lock_release(&process_exit_lock);
      
  }
  else /* but free the initial thread's command line */
  {
    //palloc_free_page (initial_process.command_line);
  }
}

/* Sets up the CPU for running user code in the current
   thread. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_set_esp0 ((uint8_t *) t + PGSIZE);
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Used in push_args_on_stack */
#define WORD_SIZE 4        /* Used for rounding ESP */     
#define DELIM " "          /* Used for parsing command-line args */
static bool load_segment (struct file *, const struct Elf32_Phdr *);
static bool setup_stack (void **esp);
static bool push_args_on_stack (void **esp, char *filename, char *save_ptr);


/* Loads an ELF executable from CMDLINE into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (struct process* this_process, void (**eip) (void), void **esp) 
{
  char *cmdline = this_process->command_line;
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  /* Variables used for parsing */
  char *filename;
  char *save_ptr;

  /* designer note: strtok_r will modify cmdline, but that's okay
   * because we only want to keep the first argument anyways */

  /* Parse executable filename from cmdline, so we can open it */
  filename = strtok_r (cmdline, DELIM, &save_ptr);
  if (filename == NULL)
    {
    goto done;
    }

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  
  /* Open executable file. */ 
  this_process->exec_file = filesys_open (filename);
  file = this_process->exec_file;
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", filename);
      goto done; 
    }
    
  /* protect this executable from writes */
  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", filename);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (!load_segment (file, &phdr))
            goto done;
          break;
        }
    }


  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;
  
  if (!push_args_on_stack (esp, filename, save_ptr)) {
    goto done;
  }

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage);

/* Loads the segment described by PHDR from FILE into user
   address space.  Return true if successful, false otherwise. */
static bool
load_segment (struct file *file, const struct Elf32_Phdr *phdr) 
{
  void *start, *end;  /* Page-rounded segment start and end. */
  uint8_t *upage;     /* Iterator from start to end. */
  off_t filesz_left;  /* Bytes left of file data (as opposed to
                         zero-initialized bytes). */

  /* Is this a read-only segment?  Not currently used, so it's
     commented out.  You'll want to use it when implementing VM
     to decide whether to page the segment from its executable or
     from swap. */
  //bool read_only = (phdr->p_flags & PF_W) == 0;

  ASSERT (file != NULL);
  ASSERT (phdr != NULL);
  ASSERT (phdr->p_type == PT_LOAD);

  /* [ELF1] 2-2 says that p_offset and p_vaddr must be congruent
     modulo PGSIZE. */
  if (phdr->p_offset % PGSIZE != phdr->p_vaddr % PGSIZE) 
    return false; 

  /* p_offset must point within file. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* [ELF1] 2-3 says that p_memsz must be at least as big as
     p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* Validate virtual memory region to be mapped.
     The region must both start and end within the user address
     space range.  We don't allow mapping page 0.*/
  start = pg_round_down ((void *) phdr->p_vaddr);
  end = pg_round_up ((void *) (phdr->p_vaddr + phdr->p_memsz));
  if (!is_user_vaddr (start) || !is_user_vaddr (end) || end < start
      || start == 0)
    return false; 

  /* Load the segment page-by-page into memory. */
  filesz_left = phdr->p_filesz + (phdr->p_vaddr & PGMASK);
  file_seek (file, ROUND_DOWN (phdr->p_offset, PGSIZE));
  for (upage = start; upage < (uint8_t *) end; upage += PGSIZE) 
    {
      /* We want to read min(PGSIZE, filesz_left) bytes from the
         file into the page and zero the rest. */
      size_t read_bytes = filesz_left >= PGSIZE ? PGSIZE : filesz_left;
      size_t zero_bytes = PGSIZE - read_bytes;
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Do the reading and zeroing. */
      if (file_read (file, kpage, read_bytes) != (int) read_bytes) 
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + read_bytes, 0, zero_bytes);
      filesz_left -= read_bytes;

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage)) 
        {
          palloc_free_page (kpage);
          return false; 
        }
    }

  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Push args on stack.  Assumes that we've already parsed the filename
   out of the cmdline string.
   Returns # of args parsed.  A 0 return value indicates an error.
    -- esp: Address of stack-pointer
    -- filename: the executable filename ("argument 0")
    -- save_ptr: The rest of the arguments, as left by strtok_r
*/
static bool
push_args_on_stack (void **esp, char *filename, char *save_ptr)
{
  int i, argc = 0;
  char *token, *argWalker;

  ASSERT(*esp == PHYS_BASE); /* Make sure we're starting at the top of
                                the page */
  
  /* Write args to stack */
  for (token = filename; 
       token != NULL; 
       token = strtok_r (NULL, DELIM, &save_ptr)) 
    {
      *esp -= (strlen(token) + 1);  /* Move down to make space */
      /* MAX_CMDSTRING_LEN, plus 1 for null terminator, is the max
         length for each argument. We already know that the args'
         combined length (with null terminator) is MAX_CMDSTRING_LEN+1
         (from when we created the copy in process_execute), so this
         is a safe upper-bound to use for any single argument
         copying */
      if (strlcpy(*esp, token, MAX_CMDSTRING_LEN + 1) >= MAX_CMDSTRING_LEN) 
        {
          return false;
        }
      ++argc;
    }
  
  /* Set argWalker to point to the last arg that was written. */
  argWalker = (char *)(*esp);

  /* Word-Align ESP.
     The char * cast is so we subtract a # of bytes, not a # of words.
     The unsigned int cast is so we can use the % operator. */
  *esp = (char *)(*esp) - ((unsigned int)(*esp) % WORD_SIZE); 
  
  /* Make sure that, after copying the arguments, we still have space
     for the argv vector. */
  void *final_esp = 
    *esp                     // Current value
    - sizeof(char*)          // For null-pointer sentinel
    - argc * sizeof(char*)   // For all the entries in argv
    - sizeof(char**)         // For argv base pointer
    - sizeof(int)            // For argc value
    - sizeof(void(*)(void)); // For fake return value
  
  if (final_esp < (PHYS_BASE - PGSIZE)) { 
    return false;
  }


  /* Add null pointer sentinel */
  *esp -= sizeof(char *); /* Make room */
  *(char **)*esp = NULL;

  /* Write args' addresses to stack */
  for (i = 0; i < argc; i++) 
    {
      *esp -= sizeof(char *);  /* Move down to make space for a char*
                                */  
      *((char **)(*esp)) = argWalker;       /* Address of argument */
      argWalker += (strlen(argWalker) + 1);  /* Advance to next
                                                argument */ 
    } 

  /* Write argv address (it's just the current stack pointer) */
  *esp -= sizeof(char **); /* Make room */
  *((char ***)(*esp)) = *esp + sizeof(char **); /* Stack pointer,
                                                   before we made room
                                                 */ 
  
  /* Write argc */
  *esp -= sizeof(int);     /* Make room */
  *((int *)(*esp)) = argc;
  

  /* Write fake return value  */
  *esp -= sizeof(void(*)(void));  /* Make room */  
  *((void **)(*esp)) = NULL;
  
  ASSERT(*esp == final_esp); /* Make sure our calculation for
                                "final_esp" was correct */
  return true;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.  Fails if UPAGE is
   already mapped or if memory allocation fails. */
static bool
install_page (void *upage, void *kpage)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, true));
}

/* get the current running process */
struct process*
process_current(void)
{
    if(thread_current()->parent_process != NULL) 
        return thread_current()->parent_process;
        
    /* this case is true for the initial thread*/
    return &initial_process;
}

/* initialize important variables and locks */
void 
process_init()
{
    lock_init(&process_exit_lock);
    initial_process.main_tid = thread_current()->tid;
    list_init(&initial_process.children);    
    initial_process.parent = NULL;
    initial_process.status = 0;
    ASSERT(dir_open_root(&initial_process.cwd));
}

/* Utility functions for converting between fd's and array-indices */
static int 
fd_to_index(int fd)
{
  return fd - FD_OFFSET;
}

static int 
index_to_fd(int index)
{
  return index + FD_OFFSET;
}


static bool
ensure_space_at_end(struct process *proc)
{
  int new_allocated_size;
  struct file **new_files;
  unsigned int *new_unused_indices UNUSED; /* UNUSED because we just
                                              store to it and then
                                              copy out of it. */ 

  ASSERT(proc->logical_size <= proc->allocated_size);

  if (proc->logical_size == proc->allocated_size-1) 
    {
      new_allocated_size = proc->allocated_size * MEM_INCREASE_FACTOR;

      /* Allocate space for double-size files array */
      new_files = 
        (struct file **)malloc(new_allocated_size * sizeof(struct file*));
      if (!new_files) 
          return false;  /* malloc failed -- not enough memory. */
      /* Copy old files array to new array */
      memcpy(new_files, proc->files, 
             proc->logical_size * sizeof(struct file*));
      free(proc->files);
      proc->files = new_files;
      proc->allocated_size = new_allocated_size;

      /* Allocate space for double-size unused_indices ring_buffer */
      unsigned int *new_buffer =
        (unsigned int *)malloc(new_allocated_size * sizeof(unsigned int*));
      if (!new_buffer) 
          return false;  /* malloc failed -- not enough memory. */

      /* we don't need to copy old entries because if we have
       * to increase the size of the list, there were obviously
       * no unused fd's left */
      free(proc->unused_indices.buffer);
      proc->unused_indices.buffer = new_buffer;
      rb_init_buff(&proc->unused_indices, new_allocated_size);
    }
  return true;
}

int 
process_store_file(struct file *file)
{
  struct process *proc = process_current();
  int index;
  if (rb_empty(&proc->unused_indices))
    {
      /* No unused indices in middle of array.  Put file at the end of
         array. */
      if (!ensure_space_at_end(proc))
        {
          /* Malloc ran out of memory when extending array. */
          return BAD_FD;
        }
      index = proc->logical_size;
      proc->logical_size++;
    }
  else 
    {
      index = rb_pop_front(&proc->unused_indices);
    }
  proc->files[index] = file;
  
  return index_to_fd(index);
}

struct file *
get_file_helper(struct process *proc, int index)
{
  if (index >= 0 && index < (int)(proc->logical_size)) 
    {
      return proc->files[index]; 
      /* Note: If index is in-bounds but unused, its entry will be NULL,
       * so we'll return NULL here, which is correct. */
    } 
  else 
    {
      return NULL;
    }
}


struct file *
process_get_file(int fd)
{
  return get_file_helper(process_current(), fd_to_index(fd));
}


struct file *
process_pop_file(int fd)
{
  struct process *proc = process_current();
  int index = fd_to_index(fd);
  struct file *the_file = get_file_helper(proc, index);
  if (the_file != NULL) {
    proc->files[index] = NULL;
    bool success = rb_push_back(&proc->unused_indices, index);
    ASSERT(success);
  }
  return the_file;
}

void
process_free_file_lists(struct process *proc)
{
    free(proc->files);
    free(proc->unused_indices.buffer);
}
