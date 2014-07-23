#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/disk.h"
#include "filesys/off_t.h"
#include <stdbool.h>

/* this must be UNALLOCATED_INDEX (-1) from inode.h in order for certain code to work. */
#define NO_READ_AHEAD ((disk_sector_t)-1)

/* this is metadata, and we shouldn't read ahead */
#define IS_METADATA ((disk_sector_t)-2)

void filesys_cache_init(void);

void filesys_cache_read(disk_sector_t sector, void *dest, off_t offset, off_t size, disk_sector_t prefetch);
void filesys_cache_write(disk_sector_t sector, const void *src, off_t offset, off_t size);

/* if this thing is in the cache, remove it, because we've deleted the file */
void filesys_cache_remove(disk_sector_t sector);

void print_cache_stats(void);

void filesys_flush_cache(void);

bool is_cache_thread(void);

#endif
