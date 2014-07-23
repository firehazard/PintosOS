#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "userprog/process.h" // for process_current().cwd

#define DIR_DELIM_CHAR '/'
#define DIR_DELIM_STR  "/"

#define DIR_NAME_SELF   "."
#define DIR_NAME_PARENT ".."

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    disk_sector_t inode_sector;         /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

// Prototypes
static bool 
is_subdir_name_reserved (const char *subdir_name);
static bool lookup (const struct dir *dir, const char *name,
                    struct dir_entry *ep, off_t *ofsp);
static bool dir_open_subdir_by_name(struct dir *dir, const char *subdir_name,
				    struct dir **dirp);
static bool dir_is_empty(const struct dir *);
static bool dir_add_helper (struct dir *dir, const char *name, 
                            disk_sector_t inode_sector);

/* Checks if the given subdirectory name is reserved. */
static bool 
is_subdir_name_reserved (const char *subdir_name)
{
  ASSERT(subdir_name != NULL);
  return ((strcmp(subdir_name, DIR_NAME_SELF) == 0) || 
          (strcmp(subdir_name, DIR_NAME_PARENT) == 0));
}

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. 
   In order to support the ".." directory entry, this function 
   also requires the sector of this directory's parent directory.
*/
bool
dir_create_with_parent_sector (disk_sector_t sector, 
                               disk_sector_t parent_sector,
                               size_t entry_cnt) 
{
  bool success;
  if ((success = inode_create (sector, entry_cnt * 
                               sizeof (struct dir_entry))))
  {
    inode_set_sector_is_dir(sector);

    // Add the "." and ".." directories 
    struct dir *the_dir;
    
    struct inode *inode = inode_open (sector);
    if ((success = (inode != NULL))) {
      if ((success = dir_open (inode, &the_dir)))
      {
        success = (dir_add_helper(the_dir, DIR_NAME_SELF, sector) &&
                   dir_add_helper(the_dir, DIR_NAME_PARENT, parent_sector));
        dir_close(the_dir);
      } 
      else
      {
        inode_close(inode);
      }
    }
  }

  return success;
}

bool
dir_create_with_parent_dir (disk_sector_t sector, 
                            struct dir *parent_dir, 
                            size_t entry_cnt) 
{
  return dir_create_with_parent_sector(sector, 
                                       inode_get_sector(parent_dir->inode), 
                                       entry_cnt);
}


/* Opens the directory in the given INODE, of which it takes
   ownership, and sets *DIRP to the new directory or a null
   pointer on failure.  Return true if successful, false on
   failure. */
bool
dir_open (struct inode *inode, struct dir **dirp) 
{
  struct dir *dir = NULL;
  
  ASSERT (dirp != NULL);
  if (inode != NULL) 
    {
      dir = malloc (sizeof *dir);
      if (dir != NULL) 
        dir->inode = inode;
    }
  
  *dirp = dir;
  if (dir == NULL)
    inode_close (inode);
  return dir != NULL;
}

/* Opens the root directory and sets *DIRP to it or to a null
   pointer on failure.  Return true if successful, false on
   failure. */
bool
dir_open_root (struct dir **dirp)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR), dirp);
}

bool
dir_reopen (const struct dir *orig_dir, struct dir **dirp)
{
  return dir_open(inode_reopen (orig_dir->inode), dirp);
}

/*
 * Opens the directory or file at the given path.  
 * Returns the resulting directory object by reference in the
 * parameter DIRP.
 *
 * If SKIP_FINAL_TOKEN is false, this function will traverse the
 * directory structure of the full path, assuming that each token is
 * an existing subdirectory of its predecessor.
 *
 * If SKIP_FINAL_TOKEN is true, this function will only traverse the
 * directory structure to the second-to-last level given in the path.
 * (for example, this would be used if the last entry in the path is a
 * file or a yet-to-be-created directory)  The final token's name will
 * then be returned by reference in FINAL_TOKEN_NAME.
 */
bool dir_open_by_name(char *path, struct dir **dirp, 
                      bool skip_final_token, char **final_token_name)
{
  char *cur_subdir_name;
  char *next_subdir_name;
  struct dir *cur_dir;
  char *save_ptr;
  bool success = false;

  // figure out where to start -- root dir or cwd
  if (strnlen(path, 1) > 0 && path[0] == DIR_DELIM_CHAR) 
  {
    if (!dir_open_root(&cur_dir)) 
    {
      *dirp = NULL;
      return false;
    }
  }
  else
  {
    if (!dir_reopen(process_current()->cwd, &cur_dir)) {
      *dirp = NULL;
      return false;
    }
  }

  next_subdir_name = strtok_r(path, DIR_DELIM_STR, &save_ptr);

  /* Drill down through the path, one level at a time */
  while(true)
  {
    cur_subdir_name = next_subdir_name;
    next_subdir_name = strtok_r(NULL, DIR_DELIM_STR, &save_ptr);

    /* Are we done?
       We're done if either of the following holds:
        - We're skipping the final subdir, and we've reached the final
           subdir (e.g. next_subdir_name is null)
        - We're not skipping the final subdir, and we've gone past the
           final subdir (e.g. cur_subdir_name is null)
      */
    if ((!skip_final_token && cur_subdir_name == NULL) ||
        (skip_final_token && next_subdir_name == NULL))
    {
      success = true;
      break;
    }
        
    // Open subdirectory.
    if (!dir_open_subdir_by_name(cur_dir, cur_subdir_name, dirp)) 
    {
      break;
    }
    else 
    {
      dir_close(cur_dir);
      cur_dir = *dirp;
    }
  }

  *dirp = cur_dir;
  /* Return the final token name by reference, if client wants it */
  if (success && skip_final_token && final_token_name != NULL) 
  {
    /* If cur_subdir_name is null, that implies we got the empty
       string. In this case, set final token to empty string. */
    *final_token_name = (cur_subdir_name == NULL ? 
                         "" : cur_subdir_name);
  }
  return success;
}

static bool 
dir_open_subdir_by_name(struct dir *dir, const char *subdir_name,
                        struct dir **subdirp)
{
  struct inode *subdir_inode;
  return (dir_lookup(dir, subdir_name, &subdir_inode) &&
          dir_open(subdir_inode, subdirp));

}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, disk_sector_t inode_sector) 
{
  if (is_subdir_name_reserved(name)) {
    return false;
  }
  return dir_add_helper(dir, name, inode_sector);
}

bool
dir_add_helper (struct dir *dir, const char *name, disk_sector_t inode_sector) 
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;


 done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Don't allow removal of "." or ".." */
  if (is_subdir_name_reserved(name)) {
    return false;
  }

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;
  
  /* If directory, make sure it's empty */
  if (inode_is_dir(inode))
  {
    struct dir *subdir;

    /* Can we open the directory? */
    /* (Use inode_reopen so that we can dir_close the directory
       without closing our original inode.) */ 
    if (!dir_open(inode_reopen(inode), &subdir))
    {
      goto done;
    }
    /* Is it empty? */
    if (!dir_is_empty(subdir)) {
      dir_close(subdir);
      goto done;
    }
    dir_close(subdir);
  }		      

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  inode_close (inode);
  return success;
}

/* Prints the names of the files in DIR to the system console. */
void
dir_list (const struct dir *dir)
{
  struct dir_entry e;
  size_t ofs;
  
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use)
      printf ("%s\n", e.name);
}

/* Checks if the given directory is empty */
bool
dir_is_empty (const struct dir *dir)
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);

  bool is_empty = true;
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
  {
    // Check if it's in use and if it matches neither "." nor ".."
    if (e.in_use && strcmp (e.name, DIR_NAME_SELF) && 
	strcmp (e.name, DIR_NAME_PARENT))
    {
      is_empty = false;
      break;
    }
  }
  return is_empty;
}
