#include "threads/init.h"
#include <console.h>
#include <debug.h>
#include <limits.h>
#include <random.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "devices/kbd.h"
#include "devices/serial.h"
#include "devices/timer.h"
#include "devices/vga.h"
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/loader.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#ifdef USERPROG
#include "userprog/process.h"
#include "userprog/exception.h"
#include "userprog/gdt.h"
#include "userprog/syscall.h"
#include "userprog/tss.h"
#else
#include "tests/threads/tests.h"
#endif
#ifdef FILESYS
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "filesys/fsutil.h"
#endif

/* Amount of physical memory, in 4 kB pages. */
size_t ram_pages;

/* Page directory with kernel mappings only. */
uint32_t *base_page_dir;

/* -mlfqs:
   If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler. */
bool enable_mlfqs;

#ifdef VM
/* -rndpg:
   If false (default), use LRU page replacement policy.
   If true, use random page replacement policy. */
bool enable_random_paging;
#endif

#ifdef FILESYS
/* -f: Format the filesystem? */
static bool format_filesys;
#endif

/* -q: Power off after kernel tasks complete? */
bool power_off_when_done;

static void ram_init (void);
static void paging_init (void);

static char **read_command_line (void);
static char **parse_options (char **argv);
static void run_actions (char **argv);
static void usage (void);

static void print_stats (void);


int main (void) NO_RETURN;

/* Pintos main program. */
int
main (void)
{
  char **argv;
  
  /* Clear BSS and get machine's RAM size. */  
  ram_init ();

  /* Initialize ourselves as a thread so we can use locks. */
  thread_init ();

  /* Initialize the console so we can use printf(). */
  vga_init ();
  serial_init_poll ();
  console_init ();

  /* Greet user. */
  printf ("Pintos booting with %'zu kB RAM...\n", ram_pages * PGSIZE / 1024);

  /* Break command line into arguments and parse options. */
  argv = read_command_line ();
  argv = parse_options (argv);

  /* Initialize memory system. */
  palloc_init ();
  malloc_init ();
  paging_init ();

  /* Segmentation. */
#ifdef USERPROG
  tss_init ();
  gdt_init ();
#endif

  /* Set random seed if parse_options() didn't. */
  random_init (0);

  /* Initialize interrupt handlers. */
  intr_init ();
  timer_init ();
  kbd_init ();

#ifdef USERPROG
  exception_init ();
  syscall_init ();
#endif

  /* Start thread scheduler and enable interrupts. */
  thread_start ();
  serial_init_queue ();
  timer_calibrate ();

#ifdef FILESYS
  /* Initialize filesystem */
  /* Must happen before process_init */
  disk_init ();
  filesys_init (format_filesys);
#endif

#ifdef USERPROG
  process_init();
#endif

  printf ("Boot complete.\n");
  
  /* Run actions specified on kernel command line. */
  run_actions (argv);

  /* Finish up. */
  if (power_off_when_done)
    power_off ();
  thread_exit ();
}

/* Clear BSS and obtain RAM size from loader. */
static void
ram_init (void) 
{
  /* The "BSS" is a segment that should be initialized to zeros.
     It isn't actually stored on disk or zeroed by the kernel
     loader, so we have to zero it ourselves.

     The start and end of the BSS segment is recorded by the
     linker as _start_bss and _end_bss.  See kernel.lds. */
  extern char _start_bss, _end_bss;
  memset (&_start_bss, 0, &_end_bss - &_start_bss);

  /* Get RAM size from loader.  See loader.S. */
  ram_pages = *(uint32_t *) ptov (LOADER_RAM_PGS);
}

/* Populates the base page directory and page table with the
   kernel virtual mapping, and then sets up the CPU to use the
   new page directory.  Points base_page_dir to the page
   directory it creates.

   At the time this function is called, the active page table
   (set up by loader.S) only maps the first 4 MB of RAM, so we
   should not try to use extravagant amounts of memory.
   Fortunately, there is no need to do so. */
static void
paging_init (void)
{
  uint32_t *pd, *pt;
  size_t page;

  pd = base_page_dir = palloc_get_page (PAL_ASSERT | PAL_ZERO);
  pt = NULL;
  for (page = 0; page < ram_pages; page++) 
    {
      uintptr_t paddr = page * PGSIZE;
      void *vaddr = ptov (paddr);
      size_t pde_idx = pd_no (vaddr);
      size_t pte_idx = pt_no (vaddr);

      if (pd[pde_idx] == 0)
        {
          pt = palloc_get_page (PAL_ASSERT | PAL_ZERO);
          pd[pde_idx] = pde_create (pt);
        }

      pt[pte_idx] = pte_create_kernel (vaddr, true);
    }

  /* Store the physical address of the page directory into CR3
     aka PDBR (page directory base register).  This activates our
     new page tables immediately.  See [IA32-v2a] "MOV--Move
     to/from Control Registers" and [IA32-v3] 3.7.5. */
  asm volatile ("mov %%cr3, %0" :: "r" (vtop (base_page_dir)));
}

/* Breaks the kernel command line into words and returns them as
   an argv-like array. */
static char **
read_command_line (void) 
{
  static char *argv[LOADER_ARGS_LEN / 2 + 1];
  char *p, *end;
  int argc;
  int i;

  argc = *(uint32_t *) ptov (LOADER_ARG_CNT);
  p = ptov (LOADER_ARGS);
  end = p + LOADER_ARGS_LEN;
  for (i = 0; i < argc; i++) 
    {
      if (p >= end)
        PANIC ("command line arguments overflow");

      argv[i] = p;
      p += strnlen (p, end - p) + 1;
    }
  argv[argc] = NULL;

  /* Print kernel command line. */
  printf ("Kernel command line:");
  for (i = 0; i < argc; i++)
    printf (" %s", argv[i]);
  printf ("\n");

  return argv;
}

/* Parses options in ARGV[]
   and returns the first non-option argument. */
static char **
parse_options (char **argv) 
{
  for (; *argv != NULL && **argv == '-'; argv++)
    {
      char *save_ptr;
      char *name = strtok_r (*argv, "=", &save_ptr);
      char *value = strtok_r (NULL, "", &save_ptr);
      
      if (!strcmp (name, "-h"))
        usage ();
      else if (!strcmp (name, "-q"))
        power_off_when_done = true;
#ifdef FILESYS
      else if (!strcmp (name, "-f"))
        format_filesys = true;
      else if (!strcmp (name, "-fs_i"))
        INIT_NUM_ACCESSED = atoi(value);
      else if (!strcmp (name, "-fs_a"))
      {
        ACCESSED_WEIGHT = atoi(value);
      }
      else if (!strcmp (name, "-fs_d"))
        DIRTY_WEIGHT = atoi(value);
      else if (!strcmp (name, "-fs_m"))
        META_WEIGHT = atoi(value);                        
#endif
      else if (!strcmp (name, "-rs"))
        random_init (atoi (value));
      else if (!strcmp (name, "-mlfqs"))
        enable_mlfqs = true;
#ifdef USERPROG
      else if (!strcmp (name, "-ul"))
        user_page_limit = atoi (value);
#endif
#ifdef VM
      else if (!strcmp (name, "-rndpg"))
        enable_random_paging = true;
#endif
      else
        PANIC ("unknown option `%s' (use -h for help)", name);

    }
  
  return argv;
}

/* Runs the task specified in ARGV[1]. */
static void
run_task (char **argv)
{
  const char *task = argv[1];
  
  printf ("Executing '%s':\n", task);
#ifdef USERPROG
  process_wait (process_execute (task));
#else
  run_test (task);
#endif
  printf ("Execution of '%s' complete.\n", task);
}

/* Executes all of the actions specified in ARGV[]
   up to the null pointer sentinel. */
static void
run_actions (char **argv) 
{
  /* An action. */
  struct action 
    {
      char *name;                       /* Action name. */
      int argc;                         /* # of args, including action name. */
      void (*function) (char **argv);   /* Function to execute action. */
    };

  /* Table of supported actions. */
  static const struct action actions[] = 
    {
      {"run", 2, run_task},
#ifdef FILESYS
      {"ls", 1, fsutil_ls},
      {"cat", 2, fsutil_cat},
      {"rm", 2, fsutil_rm},
      {"put", 2, fsutil_put},
      {"get", 2, fsutil_get},
#endif
      {NULL, 0, NULL},
    };

  while (*argv != NULL)
    {
      const struct action *a;
      int i;

      /* Find action name. */
      for (a = actions; ; a++)
        if (a->name == NULL)
          PANIC ("unknown action `%s' (use -h for help)", *argv);
        else if (!strcmp (*argv, a->name))
          break;

      /* Check for required arguments. */
      for (i = 1; i < a->argc; i++)
        if (argv[i] == NULL)
          PANIC ("action `%s' requires %d argument(s)", *argv, a->argc - 1);

      /* Invoke action and advance. */
      a->function (argv);
      argv += a->argc;
    }
  
}

/* Prints a kernel command line help message and powers off the
   machine. */
static void
usage (void)
{
  printf ("\nCommand line syntax: [OPTION...] [ACTION...]\n"
          "Options must precede actions.\n"
          "Actions are executed in the order specified.\n"
          "\nAvailable actions:\n"
#ifdef USERPROG
          "  run 'PROG [ARG...]' Run PROG and wait for it to complete.\n"
#else
          "  run TEST           Run TEST.\n"
#endif
#ifdef FILESYS
          "  ls                 List files in the root directory.\n"
          "  cat FILE           Print FILE to the console.\n"
          "  rm FILE            Delete FILE.\n"
          "Use these actions indirectly via `pintos' -g and -p options:\n"
          "  put FILE           Put FILE into file system from scratch disk.\n"
          "  get FILE           Get FILE from file system into scratch disk.\n"
#endif
          "\nOptions:\n"
          "  -h                 Print this help message and power off.\n"
          "  -q                 Power off VM after actions or on panic.\n"
          "  -f                 Format file system disk during startup.\n"
          "  -rs=SEED           Set random number seed to SEED.\n"
          "  -mlfqs             Use multi-level feedback queue scheduler.\n"
#ifdef USERPROG
          "  -ul=COUNT          Limit user memory to COUNT pages.\n"
#endif
#ifdef VM
          "  -rndpg             Use random page replacement policy.\n"
#endif
          );
  power_off ();
}


/* Powers down the machine we're running on,
   as long as we're running on Bochs or qemu. */
void
power_off (void) 
{
  const char s[] = "Shutdown";
  const char *p;

#ifdef FILESYS
  filesys_done ();
#endif

  print_stats ();

  printf ("Powering off...\n");
  serial_flush ();

  for (p = s; *p != '\0'; p++)
    outb (0x8900, *p);
  for (;;);
}

/* Print statistics about Pintos execution. */
static void
print_stats (void) 
{
  timer_print_stats ();
  thread_print_stats ();
#ifdef FILESYS
  disk_print_stats ();
#endif
  console_print_stats ();
  kbd_print_stats ();
#ifdef USERPROG
  exception_print_stats ();
#endif
}
