#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "threads/mmu.h"
#include "filesys/file.h"
#include "lib/string.h"
#include "userprog/process.h"
#include "devices/kbd.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h" /* needed for pagedir_get_page */
#include "filesys/directory.h"
#include "filesys/free-map.h"

#define FD_STDIN 0
#define FD_STDOUT 1

#define STDIO_CHUNK 100 /* don't write more than 100 characters at a
                           time to stdout */

#define INITIAL_MKDIR_SIZE 16 /* Initial number of entries in a dir created via
                                 mkdir */

/* syscall handler functions */
static void syscall_handler (struct intr_frame *);
static int syscall_wrapper(int syscall_num, void *arg0, void *arg1, void *arg2);
static void assert_valid_uaddr (const void *uaddr);
static void assert_valid_uaddr_range (const void *uaddr, int size);

/* internal syscall functions */
static void halt(void);
static void exit (int status);
static pid_t exec (const char *cmd_line);
static int wait (pid_t pid);
static bool create (const char *filename, unsigned initial_size);
static bool remove (const char *filename);
static int open (const char *filename);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);
static bool chdir(const char *dir);
static bool mkdir(const char *dir);
static void lsdir(void);

/* helper functions */
static char * user_kernel_strcpy (const char *string);
static int intmin(int first, int second);
struct file *fd_to_file_intolerant(int fd);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Takes care of extracting syscall number and determining
 * how many arguments we need to check for validity */
 
static void
syscall_handler (struct intr_frame *f) 
{
  bool addr_verified = false;
  /* Place arguments into our own pointers*/
  void *arg0 = (int *)f->esp + 1;
  void *arg1 = (int *)f->esp + 2; 
  void *arg2 = (int *)f->esp + 3;
  
  /* Check for validity of address space where syscall num is stored */
  assert_valid_uaddr(f->esp);
  /* If we got here, then address is valid and we can copy the number
   * of arguments into our stack */
  int syscall_num = *(int *)f->esp; 
  
  /* Case statement for different number of arguments.
   * We optimize number of checks to memory by using a cascading
   * switch statement (aka waterfall approach).   
   */
  switch (syscall_num) {
    /* For sys_calls with no arguments */
    case SYS_halt: case SYS_lsdir: 
      break;
    
    /* For SYS_read and SYS_write we will need 3 arguments */
    /* Hence we call a helper function to check validity of these
     * 3 arguments's addresses.
     * We also set set addr_verified to true so that we dont
     * check the address range twice.
     *  */
    case SYS_read: case SYS_write:
        assert_valid_uaddr_range (arg0, (sizeof (void *))*3);
        addr_verified = true;
    
    /*  Same as above but for 2 arguments */
    case SYS_create: case SYS_seek:
        if (!addr_verified){        
            assert_valid_uaddr_range (arg0, (sizeof (void *))*2);
            addr_verified = true;
        }
        
    /*  Same as above but for 1 argument */
    default: 
         if (!addr_verified)        
            assert_valid_uaddr_range (arg0, (sizeof (void *))*2);
  }
  /* we call a helper/wrapper function to determine the specific syscall */
  f->eax = syscall_wrapper(syscall_num, arg0, arg1, arg2);;
}


/* Kills process if user address is invalid.
 * For a user address to be valid, it must satisfy these 3 conditions:
 * 1.) The address must not be NULL
 * 2.) The address must reside below PHYS_BASE
 * 3.) The address must be mapped (and hence allocated).
 * Please note that the order of these 3 checks is critical:  If we pass
 * a kernel address to "pagedir_get_page", the O.S. will EXPLODE.  
 */  
static void
assert_valid_uaddr (const void *uaddr)
{
   if (uaddr==NULL || is_kernel_vaddr(uaddr) || 
          pagedir_get_page (thread_current()->pagedir,uaddr)==NULL)
       thread_exit();
}

/* 
 * Kills process if user range of addresses is invalid.
 * Details outlined below
 */
static void
assert_valid_uaddr_range (const void *uaddr, int size)
{
   void *kmap;
   /* curr pointer initially points at user start address */
   char *curr = (char *)uaddr; 
   int rsize = size;
   int offset;
   /* Check that initial address is not null.  If not, then
    * every address in the page should be not be null*/
   if (curr==NULL) thread_exit();
   /* We make use of a while loop in case the user gives us a range
    * that falls within multiple pages*/
   while (rsize>0){
        /* Make sure that the curr pointer falls below PHYS_BASE */
        if (is_kernel_vaddr(curr)) thread_exit();     
         /* Get the user page that corresponds to the curr pointer */
        kmap = pagedir_get_page(thread_current()->pagedir,curr);
        /* If get_page returns null, then we know we need to kill the thread */
        if (kmap==NULL) thread_exit();
        /* Find how much room we have left in that page starting from that addr*/
        offset = (char *)(pg_round_up(kmap))-(char *)kmap + 1;
        /* reduce the running size by the amount we have left in the page.  If
         * we have more room in the page than we need, then we get out of the loop */
        rsize-=offset;
        /* Increase the current pointer to the beginning of the next page */        
        curr+=offset;
   }
}

static int
syscall_wrapper(int syscall_num, void *arg0, void *arg1, void *arg2)
{
    switch (syscall_num)
    {
        case SYS_halt:
            halt(); 
            return 0;
        case SYS_exit:
            exit(*(int *)arg0);
            return 0;
        case SYS_exec: 
            return exec(*(const char **)arg0);
        case SYS_wait:
            return wait(*(pid_t *)arg0);
        case SYS_create:
            return create(*(const char **)arg0,*(unsigned *)arg1);
        case SYS_remove:
            return remove(*(const char **)arg0);
        case SYS_open:
            return open (*(const char **)arg0);
        case SYS_filesize:      
            return filesize(*(int *)arg0);
        case SYS_read:
            return read(*(int *)arg0,*(void **)arg1,*(unsigned *)arg2);
        case SYS_write:
            return write(*(int *)arg0,*(const void **)arg1,*(unsigned *)arg2);
        case SYS_seek:
            seek(*(int *)arg0,*(unsigned *)arg1);
            return 0;
        case SYS_tell:
            return tell(*(int *)arg0);
        case SYS_close:
            close(*(int *)arg0);
            return 0;
        case SYS_chdir:
          return chdir(*(const char **)arg0);
        case SYS_mkdir:
          return mkdir(*(const char **)arg0);
        case SYS_lsdir:
          lsdir();
          return 0;
        default:
            printf("INVALID SYSCALL NUMBER\n");
            thread_exit();
    }    
}


static void
halt(void)
{
  power_off();
}


static void 
exit (int status)
{
    process_current()->exitcode = status;
    thread_exit();
}

static pid_t 
exec (const char *cmd_line)
{
    /* step 1. verify that cmd_line is in valid memory */
    char *kernel_cmd_line = user_kernel_strcpy(cmd_line);
    
    /* step 2. execute cmd_line */
    pid_t rval = process_execute(kernel_cmd_line);
    free(kernel_cmd_line);

    return rval;
}

/* Creates a copy of a user string into kernel heap */
static char *
user_kernel_strcpy (const char *string)
{
   const char *iter = string; 
   char *result;
   int slack, i;
   int len = 0;
   bool found = false;
   /* If user passes a null pointer, we kill the process */
   if (iter==NULL) thread_exit();
   
   /* We have a while loop in case the user passes a string
    * that spans multiple pages */
   while (true){
        /* If we go above PHYS_BASE we kill the process */
        if (is_kernel_vaddr(iter)) thread_exit();     
        /* Ensure that the address has been user-allocated */
        if (pagedir_get_page(thread_current()->pagedir,iter)==NULL)
             thread_exit();
        /* find out how much progress we can make on the string with the
         * current page... In most cases, slack will be enough to cover 
         * the string length, but if not, then we need to check the next 
         * user page */
        slack = (char *)(pg_round_up(iter))-(char *)iter + 1;
        /* An fn similar to strnlen but with a few modifications */
        for (i=0;i<slack;i++){
             if (*iter++=='\0') {
                found = true; 
                break;
             }
             len++;
        }
        /* If we found the null character then we break */
        if (found) break;
        /* If not, then we continue checking the string in the next user
         * page */
   }
   /*malloc space for a string*/
   result = (char *)malloc(sizeof(char *)*(len+1));
   if (result==NULL) thread_exit();
   /* copy the string */
   strlcpy (result,string,len+1); 
   return result;
}

static int 
wait (pid_t pid)
{
    return process_wait(pid);
}

static bool 
create (const char *filename, unsigned initial_size)
{
    /* do some checking of filename */
    char *kernel_file = user_kernel_strcpy(filename);
    
    bool status =  filesys_create (kernel_file, initial_size);
    free(kernel_file);
    return status;
}

static bool 
remove (const char *filename)
{
    /* do some checking of filename */
    char *kernel_file = user_kernel_strcpy(filename);
    
    bool success = filesys_remove (kernel_file);
    free (kernel_file);
    return success;
}

static int 
open (const char *filename)
{
    struct file *f;
    int fd;

    char *kernel_file = user_kernel_strcpy(filename);
    
    /* step 1. Attempt to open the file (wrapped in filesys lock */
    f = filesys_open(kernel_file); 
    
    free(kernel_file);
    
    if (f == NULL)
        return BAD_FD;
    
    /* step 2. If valid file, give it to process.  */
    fd = process_store_file(f);
    
    /* Note: If anything bad happened in process_store_file, then fd
       will be already be set to BAD_FD */
    return fd;
}

static int 
filesize (int fd)
{
    struct file *f = NULL;

    f = fd_to_file_intolerant(fd);
    return file_length(f);
}

static int 
read (int fd, void *buffer, unsigned size)
{
    unsigned read_size = 0;
    struct file *f = NULL;
    
    /* step 1. verify that buffer points to a valid address */ 
    assert_valid_uaddr_range (buffer,size);

    /* step 2. determine if read is from stdin, instead of a file */
    if(fd == FD_STDIN)
    {
        while(read_size < size)
            ((char*)buffer)[read_size++] = kbd_getc();
        
        return read_size;
    }
    
    /* step 3. Get the file and read from it. */
    f = fd_to_file_intolerant(fd);

    /* Found the file.  Read from it. */
    return file_read(f, buffer, size);
}

static int
write (int fd, const void *buffer, unsigned size)
{    
    unsigned written = 0;
    int temp;
    struct file *f = NULL;

    /* step 1. verify that buffer points to a valid address */    
    assert_valid_uaddr_range (buffer, size);
    
    /* step 2. determine write is to screen, instead of a file */
    if(fd == FD_STDOUT)
    {
        /* this code will write chunks of size STDIO_CHUNK to the screen */
        while(written < size)
        {
            temp = intmin(STDIO_CHUNK, size-written);
            written += temp;
            putbuf((const char*)buffer, temp);
        }
        
        return written;
    }
    
    /* step 3. Get the file and write to it. */
    f = fd_to_file_intolerant(fd);
   
    /* Found the file.  Write to it. */
    return file_write(f, buffer, size);
}

static void 
seek (int fd, unsigned position)
{
    struct file *f = NULL;

    f = fd_to_file_intolerant(fd);

    file_seek(f, position);
}

static unsigned 
tell (int fd)
{
    struct file *f = NULL;

    f = fd_to_file_intolerant(fd);
        
    return file_tell(f);
}

static void 
close (int fd)
{
    struct file *f;
    /* step 1. Pop the corresponding file* */
    f = process_pop_file(fd);  
    if (f == NULL) 
      thread_exit();   /* Bad fd */

    /* step 2. Close the file */
    file_close(f);
}

static bool chdir(const char *dir_name)
{
  struct dir *new_dir;
  
  /* Make local copy of dir_name */
  char *kernel_dir_name = user_kernel_strcpy(dir_name);

  /* Try to open dir */
  bool success = dir_open_by_name(kernel_dir_name, &new_dir, false, NULL);

  if (success) 
  {   
    /* Close old working directory and store new one */
    dir_close(process_current()->cwd);
    process_current()->cwd = new_dir;
  }

  /* Free local copy of dir_name */
  free(kernel_dir_name);
  return success;
}

static bool mkdir(const char *dir_name)
{
  struct dir *final_parent_dir;
  char *final_subdir_name;
  disk_sector_t sector;
  bool success = false;

  /* Make local copy of dir_name */
  char *kernel_dir_name = user_kernel_strcpy(dir_name);

  if(dir_open_by_name(kernel_dir_name,  /* Go to dir's parent */
                      &final_parent_dir,
                      true, 
                      &final_subdir_name))
  {
    if (free_map_allocate(1, &sector)) /* Alloc a sector for dir */
    {
      /* Create dir in the new sector */
      if (dir_create_with_parent_dir(sector, final_parent_dir,
                                     INITIAL_MKDIR_SIZE)) 
      {
        if (dir_add(final_parent_dir,  /* Add dir to its parent's listing */
                    final_subdir_name, sector)) 
        {
          success = true;
        }
        else
        {
          free_map_release(sector, 1); /*Free sector if we couldn't add subdir*/
        }
      }
      else
      {
        free_map_release(sector, 1); /* Free sector if we couldn't
                                       create subdir */
      }
    }
  }
   // Close parent directory
  dir_close(final_parent_dir);


  /* Free space used for local copy of dir_name */  
  free (kernel_dir_name);
  return success;
}

static void lsdir(void)
{
  dir_list(process_current()->cwd);
}


/* small helper function to find min number */
static int
intmin(int first, int second)
{
  return (first < second ? first : second);
}

struct file *
fd_to_file_intolerant(int fd)
{
    struct file *f = process_get_file(fd);
    if (f == NULL)
      thread_exit();  /* Bad fd -- kill thread. */
    return f;
}
