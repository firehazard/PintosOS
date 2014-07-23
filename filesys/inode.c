#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/cache.h"
#include "threads/synch.h"
#include "lib/stdio.h"

/* Identifies an inode and other stuff. */
#define INODE_MAGIC 0x494e4f41

/* some data constants */
#define SIZE_OF_INT 4
#define DIRECT_LINKS 12
#define INDIRECT_LINKS 3

#define INDIRECT_BLOCK_OFFSET 0
#define INDIRECT_BLOCKS_PER_SECTOR 128

#define INODE_DATA_COUNT 439
#define INODE_DATA_OFFSET 1

#define DATA_BLOCK_DATA_COUNT (DISK_SECTOR_SIZE)
#define DATA_BLOCK_OFFSET 0

#define UNALLOCATED_INDEX ((disk_sector_t)-1)
#define DISK_FULL ((disk_sector_t)-2)

#define INODE_FILE_SIZE_OFFSET 440
#define INODE_DIRECT_BLOCKS_OFFSET 448
#define INODE_INDIRECT_BLOCKS_OFFSET 496
#define INODE_DOUBLE_INDIRECT_BLOCKS_OFFSET 508

/* inode_disk status bit definitions */
#define INODE_STATUS_IN_USE (1 << 0)
#define INODE_STATUS_IS_DIR (1 << 1)


/* On-disk indirect (or double-indirect block)
   Must be exactly DISK_SECTOR_SIZE bytes long. */
struct indirect_block_disk
{
  disk_sector_t sectors[INDIRECT_BLOCKS_PER_SECTOR];
};

/* On-disk data block
   Must be exactly DISK_SECTOR_SIZE bytes long. */
struct data_block_disk
{
  unsigned char data[DATA_BLOCK_DATA_COUNT];
};

/* On-disk inode.
   Must be exactly DISK_SECTOR_SIZE bytes long.
   The "used/unused" bit is cleared when a file is deleted, for safety
   purposes */
struct inode_disk
  {
    unsigned char status_bits;             /* bit 0 - used/unused.
                                              bit 1 - is_directory 
                                              bit 2-7 - unused */
    unsigned char data[INODE_DATA_COUNT];  /* file data - esp. for small files
					      */ 

    off_t file_size;                       /* file size */
    unsigned int magic;                    /* Magic number */

    /* links to data */
    disk_sector_t direct_links[DIRECT_LINKS];
    disk_sector_t indirect_links[INDIRECT_LINKS];
    disk_sector_t double_i_link;
  };

/* In-memory inode. */
struct inode 
  { 
    struct list_elem elem;              /* Element in inode list. */
    disk_sector_t sector;               /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock inode_lock;             /* lock for inode metadata */
  };
  
/* mondo helpers */
void free_sector(disk_sector_t sector);
int free_indirect_block(disk_sector_t sector, int indirection_level,
			int freed, int file_size);
void free_all_blocks(struct inode* inode);
disk_sector_t byte_to_sector_indirect(disk_sector_t *sector, off_t offset,
				      int indirection_level,bool write_blocks);
void increase_file_size(struct inode *inode, off_t size);
void filesys_cache_write_sector(disk_sector_t sector, const void *src);
disk_sector_t get_read_ahead(struct inode *inode, off_t pos);
disk_sector_t create_indirect_block(void);
bool check_status_bits(struct inode *inode, unsigned char bitmask);
void set_status_bits(struct inode *inode, unsigned char bitmask);

void filesys_cache_write_sector(disk_sector_t sector, const void *src)
{
  filesys_cache_write(sector, src, 0, DISK_SECTOR_SIZE);
}

/* creates an indirect block, and sets all of its pointers to unallocated */
disk_sector_t create_indirect_block(void)
{
  int i;
  disk_sector_t sector;
  struct indirect_block_disk* id_block;
  id_block = calloc(1, sizeof *id_block);
            
  if(!free_map_allocate (1, &sector))
  {
    return DISK_FULL;
  }
  for(i=0;i<INDIRECT_BLOCKS_PER_SECTOR;i++)
    id_block->sectors[i] = UNALLOCATED_INDEX;
    
  filesys_cache_write_sector(sector, id_block);
    
  free(id_block);
    
  return sector;  
}

/* byte_to_sector_write
 *  returns the sector which is where a file's byte should be.
 *  this function will create the sector if it hasn't been allocated yet.
 *  returns inode->sector if the position is actually part of the inode.
 * 
 * the difference between byte_to_sector_read and byte_to_sector_write is that
 * if _read realizes that a sector isn't allocated yet, it will return 0, which
 * means that the code should read out zero's. if _write happens upon this, it
 * will create the appropriate sector. otherwise these functions are the same*/
static disk_sector_t 
byte_to_sector (struct inode *inode, off_t pos, bool write_blocks)
{
  ASSERT (inode != NULL);
  
  disk_sector_t result;
  int filesize; 
    
  /* for the direct/indirect blocks */
  disk_sector_t block;
  int index;

  /* lock while we traverse metadata */
  lock_acquire(&inode->inode_lock);
  
  /* read in the file size */
  filesys_cache_read(inode->sector, &filesize, INODE_FILE_SIZE_OFFSET, 
		     SIZE_OF_INT, IS_METADATA);
    
  /* if we are reading beyond the file, return */
  if(pos > filesize && !write_blocks)
  {
    result = UNALLOCATED_INDEX;
  }
  /* if the data can fit within our inode */
  if(pos < INODE_DATA_COUNT) 
  {
    result = inode->sector;
  }  
  /* if it's a direct link */
  else if((pos -= INODE_DATA_COUNT) < DIRECT_LINKS*DATA_BLOCK_DATA_COUNT) 
  {
    index = pos / DATA_BLOCK_DATA_COUNT;
    /* read in this direct link */
    filesys_cache_read(inode->sector, &block, INODE_DIRECT_BLOCKS_OFFSET + 
		       SIZE_OF_INT * index, SIZE_OF_INT, IS_METADATA);
   
    if(block == UNALLOCATED_INDEX && write_blocks)
    {
	if(!free_map_allocate (1, &block))
	  {
	    lock_release(&inode->inode_lock);
	    return DISK_FULL;
	  }

      /* write out this change */
      filesys_cache_write(inode->sector, &block, INODE_DIRECT_BLOCKS_OFFSET + 
			  SIZE_OF_INT * index, SIZE_OF_INT);
    }
    result = block;
  }
  /* if it's an indirect link */
  else if ((pos -= DIRECT_LINKS*DATA_BLOCK_DATA_COUNT) < 
	   INDIRECT_LINKS*DATA_BLOCK_DATA_COUNT*INDIRECT_BLOCKS_PER_SECTOR)
  {
    index = pos / (DATA_BLOCK_DATA_COUNT*INDIRECT_BLOCKS_PER_SECTOR);
    filesys_cache_read(inode->sector, &block, INODE_INDIRECT_BLOCKS_OFFSET + 
		       SIZE_OF_INT * index, SIZE_OF_INT, IS_METADATA);
    
    if(block == UNALLOCATED_INDEX && write_blocks) /* not made yet */
    {
      block = create_indirect_block();
      if(block == DISK_FULL)
	{
	  lock_release(&inode->inode_lock);
	  return DISK_FULL;
	}
      filesys_cache_write(inode->sector, &block, INODE_INDIRECT_BLOCKS_OFFSET +
			  SIZE_OF_INT * index, SIZE_OF_INT);
    }
    
    result = byte_to_sector_indirect(&block, 
      pos - index * DATA_BLOCK_DATA_COUNT*INDIRECT_BLOCKS_PER_SECTOR, 0, 
				     write_blocks);
  }
  else /* otherwise it must be a doubly-indirect link */
  {
    pos -= INDIRECT_LINKS*DATA_BLOCK_DATA_COUNT*INDIRECT_BLOCKS_PER_SECTOR;
    filesys_cache_read(inode->sector, &block, 
		       INODE_DOUBLE_INDIRECT_BLOCKS_OFFSET, SIZE_OF_INT, 
		       IS_METADATA);

    if(block == UNALLOCATED_INDEX && write_blocks) /* not made yet */
    {
      block = create_indirect_block();
      if(block == DISK_FULL)
	{
	  lock_release(&inode->inode_lock);
	  return DISK_FULL;
	}
      filesys_cache_write(inode->sector, &block, 
			  INODE_DOUBLE_INDIRECT_BLOCKS_OFFSET, SIZE_OF_INT);
    }     
    
    result = byte_to_sector_indirect(&block, pos, 1, write_blocks);    
  }

  lock_release(&inode->inode_lock);

  return result;
}       

/* this function reads in an indirect block for the sector at "pos". if the
 * sector has not been initialized, it will find a free sector. we expect that
 * this indirect block has already been created. if write_blocks is false,
 * this will return UNALLOCATED_INDEX if the block isn't found */
disk_sector_t byte_to_sector_indirect(disk_sector_t *sector, off_t pos,
  int indirection_level, bool write_blocks)
{
    disk_sector_t result = UNALLOCATED_INDEX;
    disk_sector_t block;
    int index;
        
    /* create this indirect block if necessary */
    if(*sector == UNALLOCATED_INDEX)
        return *sector;
    
    if(indirection_level > 0)
    {
      index = pos / DATA_BLOCK_DATA_COUNT*INDIRECT_BLOCKS_PER_SECTOR;     
      filesys_cache_read(*sector, &block, INDIRECT_BLOCK_OFFSET + 
			 SIZE_OF_INT * index, SIZE_OF_INT, IS_METADATA);
      
      if(block == UNALLOCATED_INDEX && write_blocks) /* not made yet */
      {
        block = create_indirect_block();
	if(block == DISK_FULL)
	  return DISK_FULL;
        filesys_cache_write(*sector, &block, INDIRECT_BLOCK_OFFSET + 
			    SIZE_OF_INT * index, SIZE_OF_INT);        
      }
    
      result = byte_to_sector_indirect(&block,
        pos - index * DATA_BLOCK_DATA_COUNT*INDIRECT_BLOCKS_PER_SECTOR, 
				       indirection_level-1, write_blocks);
    }
    else
    {
      index = pos / DATA_BLOCK_DATA_COUNT;
      filesys_cache_read(*sector, &block, INDIRECT_BLOCK_OFFSET + 
			 SIZE_OF_INT * index, SIZE_OF_INT, IS_METADATA);
      
      /* if it's unallocated & we're writing, make it */
      if(block == UNALLOCATED_INDEX && write_blocks)
      {
        struct data_block_disk* dt_block;
        int i;
        
        dt_block = calloc(1, sizeof *dt_block);
	if(!free_map_allocate (1, &block))
	  {
	    free(dt_block);
	    return DISK_FULL;
	  }
              
        for(i=0;i<DATA_BLOCK_DATA_COUNT;i++)
          dt_block->data[i] = 0;
          
        /* write this 0'd out data block, and our own indirect list */
        filesys_cache_write_sector(block, dt_block);       
        free(dt_block);        
        filesys_cache_write(*sector, &block, INDIRECT_BLOCK_OFFSET + 
			    SIZE_OF_INT * index, SIZE_OF_INT);
      }
      
      result = block;
    }
    
    return result;
}

/* this function figures out which sector we should be reading ahead, if any */
disk_sector_t get_read_ahead(struct inode *inode, off_t pos)
{
  disk_sector_t result = byte_to_sector(inode, pos + DISK_SECTOR_SIZE, false);
  
  if(result == UNALLOCATED_INDEX)
    return NO_READ_AHEAD;
  return result;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

static struct lock open_inodes_lock;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  lock_init (&open_inodes_lock);
  filesys_cache_init();
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   disk.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  int i;

  ASSERT (length >= 0);
  ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);
  ASSERT (sizeof(struct data_block_disk) == DISK_SECTOR_SIZE);
  ASSERT (sizeof(struct indirect_block_disk) == DISK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
  {
      disk_inode->file_size = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->status_bits = INODE_STATUS_IN_USE;

      /* zero my brotha! */
      for(i=0;i<INODE_DATA_COUNT;i++)
        disk_inode->data[i] = 0;
        
      for(i=0;i<DIRECT_LINKS;i++)
        disk_inode->direct_links[i] = UNALLOCATED_INDEX;
      
      for(i=0;i<INDIRECT_LINKS;i++)
        disk_inode->indirect_links[i] = UNALLOCATED_INDEX;
        
      disk_inode->double_i_link = UNALLOCATED_INDEX;
     
      /* write this new inode out, entire sector */
      filesys_cache_write_sector (sector, disk_inode);
      free (disk_inode);
  }
  else
    return false;
    
  return true;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) 
{
  struct list_elem *e;
  struct inode *inode;
  
 lock_acquire(&open_inodes_lock);

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode = inode_reopen (inode);
          lock_release(&open_inodes_lock);
          return inode; 
        }
    }
    
  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->inode_lock);
  list_push_front (&open_inodes, &inode->elem);
  
  lock_release(&open_inodes_lock);
  
  /* confirm that this is indeed a valid sector with an inode */
  if(!check_status_bits(inode, INODE_STATUS_IN_USE))
  {
    printf("Protection Violation: User tried to open a non-inode sector\n");
    return NULL;
  }

  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode) 
{
  lock_acquire(&inode->inode_lock);
  if (inode != NULL) 
    inode->open_cnt++;
  lock_release(&inode->inode_lock);
  return inode;
}

/* this function will free the sector and remove it from the cache */
void free_sector(disk_sector_t sector)
{ 
  if(sector == UNALLOCATED_INDEX)
    return;
  free_map_release(sector, 1);
  filesys_cache_remove(sector);  
}

int free_indirect_block(disk_sector_t sector, int indirection_level, 
			int freed, int file_size)
{
  int i;
  if(sector == UNALLOCATED_INDEX)
    return freed;
    
  /* step 1 - read the block from disk */
  struct indirect_block_disk* id_block;
  
  id_block = calloc(1, sizeof *id_block);
 
  if(id_block != NULL)
  {
    filesys_cache_read(sector, id_block, 0, DISK_SECTOR_SIZE, IS_METADATA);
    
    for(i=0;i < INDIRECT_BLOCKS_PER_SECTOR;i++)
    {
      if(indirection_level > 0)
        freed = free_indirect_block(id_block->sectors[i], indirection_level-1, 
				    freed, file_size);
      else
      {
        free_sector(id_block->sectors[i]); 
        freed += DISK_SECTOR_SIZE;
      }
      
      if(freed >= file_size)
        break;
    }
        
    free(id_block);        
  }
  
  free_sector(sector);
  
  return freed;
}

/* this frees all blocks associated with a file! */
void free_all_blocks(struct inode* inode)
{
  disk_sector_t block;
  int i;
  int freed = 0;
  int file_size;
  
  /* read in the file size */
  filesys_cache_read(inode->sector, &file_size, INODE_FILE_SIZE_OFFSET, 
		     SIZE_OF_INT, IS_METADATA);
  
  /* free all the direct blocks */
  for(i=0;i<DIRECT_LINKS;i++)
  {
    filesys_cache_read(inode->sector, &block, INODE_DIRECT_BLOCKS_OFFSET + 
		       i*SIZE_OF_INT, SIZE_OF_INT, IS_METADATA);
    if(freed += DISK_SECTOR_SIZE < file_size)
      free_sector(block);
  }
      
  /* free all the indirect blocks */
  for(i=0;i<INDIRECT_LINKS;i++)
  {
    filesys_cache_read(inode->sector, &block, INODE_INDIRECT_BLOCKS_OFFSET + 
		       i*SIZE_OF_INT, SIZE_OF_INT, IS_METADATA);
    freed = free_indirect_block(block, 0, freed, file_size);
  }

  /* free the double-indirect block */
  filesys_cache_read(inode->sector, &block,INODE_DOUBLE_INDIRECT_BLOCKS_OFFSET,
		     SIZE_OF_INT, IS_METADATA);
  free_indirect_block(block, 1, freed, file_size);
  
  /* mark this inode as unused. don't remove from cache because we want this
     to be written to disk (for protection) */

  char zero = 0;
  filesys_cache_write(inode->sector, &zero, 0, 1);
  free_map_release(inode->sector, 1);
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;
    
  lock_acquire(&open_inodes_lock);
  lock_acquire(&inode->inode_lock);

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_all_blocks(inode);          
        }

      free (inode); 
      lock_release(&open_inodes_lock);
      return;
    }
    
  lock_release(&inode->inode_lock);
  lock_release(&open_inodes_lock);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  int i = 0;
    
  int sector_left, min_left;
  off_t sector_ofs;
  
  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset, false);
      off_t inode_left = inode_length (inode) - offset;
      
      if(sector_idx == inode->sector) /* read from the inode sector */
      {
        sector_ofs = INODE_DATA_OFFSET + offset;         
        sector_left = INODE_DATA_COUNT - offset;        
      }
      else
      {
        sector_ofs = DATA_BLOCK_OFFSET + ((offset - INODE_DATA_COUNT) % 
					  DATA_BLOCK_DATA_COUNT);
        sector_left = DISK_SECTOR_SIZE - sector_ofs;
      }

      min_left = inode_left < sector_left ? inode_left : sector_left;
  
      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      /* if we haven't allocated it yet, return 0's */
      if(sector_idx == UNALLOCATED_INDEX) 
      {
        for(i=0;i<chunk_size;i++)
          *(buffer + bytes_read + i) = 0;          
      }
      else 
          filesys_cache_read (sector_idx, buffer + bytes_read, sector_ofs, 
            chunk_size, get_read_ahead(inode, offset));
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;

  off_t sector_ofs;
  int sector_left;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      disk_sector_t sector_idx = byte_to_sector (inode, offset, true);
      if(sector_idx == DISK_FULL)
	break;

      if(sector_idx == inode->sector) /* read from the inode */
      {
        sector_ofs = INODE_DATA_OFFSET + offset;         
        sector_left = INODE_DATA_COUNT - offset;        
      }
      else
      {
        sector_ofs = DATA_BLOCK_OFFSET + ((offset - INODE_DATA_COUNT) % 
					  DATA_BLOCK_DATA_COUNT);
        sector_left = DISK_SECTOR_SIZE - sector_ofs;
      }

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < sector_left ? size : sector_left;
      if (chunk_size <= 0)
        break;
        
      filesys_cache_write (sector_idx, buffer + bytes_written, sector_ofs, 
			   chunk_size);
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;

      /* extend the file size if necessary */
      if(offset > inode_length (inode))  
        increase_file_size(inode, offset);

      bytes_written += chunk_size;
    }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  lock_acquire(&inode->inode_lock);
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  lock_release(&inode->inode_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  lock_acquire(&inode->inode_lock);
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release(&inode->inode_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (struct inode *inode)
{ 
  lock_acquire(&inode->inode_lock);
  off_t result;
  filesys_cache_read(inode->sector, &result, INODE_FILE_SIZE_OFFSET, 
		     SIZE_OF_INT, IS_METADATA);
  lock_release(&inode->inode_lock);
  
  return result;
}

void increase_file_size(struct inode *inode, off_t size)
{
  lock_acquire(&inode->inode_lock);
  filesys_cache_write(inode->sector, &size, INODE_FILE_SIZE_OFFSET, 
		      SIZE_OF_INT);  
  lock_release(&inode->inode_lock);
}

/* Checks whether the given inode is for a directory. */
bool
inode_is_dir(struct inode *inode)
{
  return check_status_bits(inode, INODE_STATUS_IS_DIR);
}

/* Marks the given inode as a directory. */
void
inode_set_is_dir(struct inode *inode)
{
  return set_status_bits(inode, INODE_STATUS_IS_DIR);
}

/* Marks the given sector as a directory. */
void
inode_set_sector_is_dir(disk_sector_t sector)
{
  unsigned char status_bits;
  filesys_cache_read (sector, &status_bits, 0, 1, IS_METADATA);
  status_bits |= INODE_STATUS_IS_DIR;
  filesys_cache_write (sector, &status_bits, 0, 1);
}

/* Checks the status_bits of the inode stored in SECTOR using the
   given BITMASK. Returns true iff any bits set in the mask are also
   set in status_bits. */
bool 
check_status_bits(struct inode *inode, unsigned char bitmask)
{
  unsigned char status_bits;
  lock_acquire(&inode->inode_lock);
  filesys_cache_read (inode->sector, &status_bits, 0, 1, IS_METADATA);
  lock_release(&inode->inode_lock);
  return (status_bits & bitmask);
}

/* Fetches the inode stored in SECTOR and sets its status_bits
   according to the BITMASK.  Does not clear any bits that were
   previously set. */
void 
set_status_bits(struct inode *inode, unsigned char bitmask)
{
  unsigned char status_bits;
  lock_acquire(&inode->inode_lock);
  filesys_cache_read (inode->sector, &status_bits, 0, 1, IS_METADATA);
  status_bits |= bitmask;
  filesys_cache_write (inode->sector, &status_bits, 0, 1);
  lock_release(&inode->inode_lock);
}

disk_sector_t
inode_get_sector(struct inode *inode)
{
  return inode->sector;
}
