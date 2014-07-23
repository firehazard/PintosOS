#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "lib/kernel/hash.h"  
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "devices/timer.h"
#include "devices/disk.h"
#include "lib/kernel/bitmap.h"
#include "lib/kernel/list.h"
#include "threads/init.h"
#include <string.h>
#include <debug.h>
#include <stdio.h>

#define DIRTY_BIT (1<<7)
#define META_BIT  (1<<6)
#define ACCESSED_BITS ((1<<6) - 1)

#define FLUSH_SLEEP_SECONDS 30
#define CACHE_ZERO_SLEEP_MSECONDS 500

//TWEAK THESE TO CHANGE CACHE MISSES
#define ENABLE_PREFETCH true
/*#define INIT_NUM_ACCESSED 5
#define ACCESSED_WEIGHT 5
#define DIRTY_WEIGHT 1
#define META_WEIGHT 32

#define MAX_SCORE (ACCESSED_WEIGHT*64 + DIRTY_WEIGHT + META_WEIGHT + 1)*/

int INIT_NUM_ACCESSED = 5;
int ACCESSED_WEIGHT = 5;
int DIRTY_WEIGHT = 1;
int META_WEIGHT = 32;

int MAX_SCORE;

static struct hash cache_hash;
static struct lock cache_hash_lock;

static bool flush_thread_alive;
static struct lock flush_thread_lock;

static struct bitmap *prefetch_list;
static struct lock prefetch_list_lock;


//TODO: change struct sector_data to unsigned char array
// so that we dont have to malloc it
struct cache_hash_entry
{
  struct hash_elem h_elem; 
  disk_sector_t sector; //hash_key
  void *sector_data; //sector data
  char sector_info;
  struct lock sector_lock;
  int ref_count;
  bool is_removed;
};

struct sector_to_evict 
{
  struct list_elem elem;
  struct cache_hash_entry *evictee;
};
 
static struct list eviction_list; 
static struct lock eviction_list_lock;

#define MAX_ENTRIES 64

/* locked with the global cache hash lock. this lists the actual allowed # of entries in the hash. when we
 * are removing a file, we decrement this so we will not have 65 entries (63 in hash, the 1 we removed from the
 * hash and didn't free, and 1 new entry that is being added) */
static unsigned cache_allowed_entries = MAX_ENTRIES;

//Temporary cache globals for our own amusement, quite thread unsafe too but who cares
static int num_misses;
static int num_evictions;

static unsigned cache_hash_fn(const struct hash_elem *e, void *aux UNUSED);
static bool cache_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
struct cache_hash_entry * lookup_cache_entry(disk_sector_t sector);
void cache_out(void);
void increase_accessed (struct cache_hash_entry* entry);
void decrease_accessed (struct cache_hash_entry* entry);
static int evict_score(const struct cache_hash_entry* entry);
void print_sector_info(char* str, const struct cache_hash_entry *entry);
static void sleep_and_flush(void *aux UNUSED);
static void prefetch_me(void *aux);
bool look_and_lock(disk_sector_t sector, struct cache_hash_entry **entry_ptr);
void copy_and_unlock (struct cache_hash_entry *entry, void *dest, const void *src, size_t size);
struct cache_hash_entry *setup_cache_entry(disk_sector_t sector);


void filesys_cache_init()
{
    MAX_SCORE = (ACCESSED_WEIGHT*64 + DIRTY_WEIGHT + META_WEIGHT + 1);
    hash_init(&cache_hash, cache_hash_fn, cache_less, NULL);
    lock_init(&cache_hash_lock);
    lock_init(&flush_thread_lock);
    lock_init(&prefetch_list_lock);
    lock_init(&eviction_list_lock);
    list_init(&eviction_list);
    flush_thread_alive = false;
    num_misses = 0;
    num_evictions = 0; 
    prefetch_list = bitmap_create((size_t)disk_size(filesys_disk));
}

//TODO: incorporate eviction list?
void filesys_cache_remove(disk_sector_t sector)
{
    lock_acquire(&cache_hash_lock);
    struct cache_hash_entry* entry = lookup_cache_entry(sector);
    if (entry==NULL){
      lock_release(&cache_hash_lock);
      return;
    }
    lock_acquire(&entry->sector_lock);
    hash_delete(&cache_hash, &entry->h_elem);
    lock_release(&entry->sector_lock);
    lock_release(&cache_hash_lock);
    free(entry->sector_data);
    free(entry);

    lock_acquire(&cache_hash_lock);
    lock_release(&cache_hash_lock);
}

//Make sure you do synch outside this function
struct cache_hash_entry *
lookup_cache_entry(disk_sector_t sector)
{
  struct cache_hash_entry tmp_cache_hash_entry, *result;
  tmp_cache_hash_entry.sector = sector;

  struct hash_elem *found_elem = 
    hash_find(&cache_hash, &tmp_cache_hash_entry.h_elem);

  if (found_elem==NULL) result= NULL;
  else result = hash_entry (found_elem, struct cache_hash_entry, h_elem);

  return result;
}


void filesys_cache_read(disk_sector_t sector, void *dest, off_t offset,  off_t size, disk_sector_t prefetch)
{
  ASSERT(offset + size <= DISK_SECTOR_SIZE);
  struct cache_hash_entry *entry;
  bool is_new_entry = look_and_lock(sector,&entry);
  
  if (is_new_entry) {
    if(prefetch==IS_METADATA) 
      entry->sector_info |= META_BIT;
    num_misses++;
    disk_read(filesys_disk, sector, entry->sector_data); 
  }
  
  copy_and_unlock (entry, dest,entry->sector_data + offset, size);

  if(prefetch!=NO_READ_AHEAD && prefetch!=IS_METADATA && ENABLE_PREFETCH) {
    lock_acquire(&prefetch_list_lock);
    if (!bitmap_test(prefetch_list,(size_t)prefetch)){
      bitmap_set (prefetch_list,(size_t)prefetch, true);
      lock_release(&prefetch_list_lock);
      thread_create ("prefetch", PRI_DEFAULT - 1, prefetch_me, (void *)sector); 
    } else lock_release(&prefetch_list_lock);
  }

}

bool is_cache_thread(){
    return (strcmp(thread_current()->name,"sleeping_beauty")==0 ||
            strcmp(thread_current()->name,"prefetch")==0);
    
}

static void
prefetch_me(void *aux)
{
  struct cache_hash_entry* entry;
  if (look_and_lock((disk_sector_t)aux, &entry))  
     disk_read(filesys_disk,(disk_sector_t)aux, entry->sector_data);
  lock_release(&entry->sector_lock);
}

void copy_and_unlock (struct cache_hash_entry *entry, void *dest, const void *src, size_t size)
{
  increase_accessed(entry);
  entry->ref_count++;
  lock_release(&entry->sector_lock);
  memcpy ((uint8_t *)dest,(uint8_t *)src, size);
  lock_acquire(&entry->sector_lock);
  entry->ref_count--;
  
  /* check if this is the last referencer, and we are evicting it */  
  /*lock_acquire(&eviction_list_lock);
  struct list_elem *e;
  for (e = list_begin (&eviction_list); e != list_end (&eviction_list); )
  {
      struct sector_to_evict *f = list_entry (e, struct sector_to_evict, elem); 
         
      e = list_next (e);
      if (f->evictee==entry && entry->ref_count == 0)
      {
        disk_write(filesys_disk, f->evictee->sector, f->evictee->sector_data); 
        free(entry->sector_data);
        free(entry);
                
        // we've finally freed this entry. allow more entries in the hash. 
        cache_allowed_entries++;
        list_remove(&f->elem); 
        free(f);
        lock_release(&eviction_list_lock);
        return;
      }
  }
  lock_release(&eviction_list_lock);*/
  
  if(entry->is_removed && entry->ref_count == 0)
  {
    disk_write(filesys_disk, entry->sector, entry->sector_data); 
    free(entry->sector_data);
    free(entry);
            
    // we've finally freed this entry. allow more entries in the hash. 
    cache_allowed_entries++;
    return;
  }
  lock_release(&entry->sector_lock);
}

bool
look_and_lock(disk_sector_t sector, struct cache_hash_entry **entry_ptr)
{
  lock_acquire(&cache_hash_lock);

  //TODO: Look over this while loop... is probably not ideal
  //very CRITICAL SECTION
  /*lock_acquire(&eviction_list_lock);
  struct list_elem *e;
  bool in_eviction_list = true;
  
  while (in_eviction_list) {
    in_eviction_list = false;
    for (e = list_begin (&eviction_list); e != list_end (&eviction_list); )
      {
    	struct sector_to_evict *f = list_entry (e, struct sector_to_evict, elem); 
      
	    if (f->evictee->sector==sector && f->evictee->ref_count>0)
	       in_eviction_list = true;
         
      e = list_next (e)
      if (f->evictee->ref_count==0){
          disk_write(filesys_disk, f->evictee->sector, f->evictee->sector_data); 
    	    free(f->evictee->sector_data);
          free(f->evictee);
              
          // we've finally freed this entry. allow more entries in the hash. 
          cache_allowed_entries++;
      	  list_remove(e); 
        }
      }
  }
  
  lock_release(&eviction_list_lock);*/

  *entry_ptr = lookup_cache_entry((disk_sector_t)sector);
  bool is_new_entry = (*entry_ptr == NULL);
  if (is_new_entry)
    *entry_ptr = setup_cache_entry(sector);
  lock_acquire(&(*entry_ptr)->sector_lock);
  lock_release(&cache_hash_lock);
  return is_new_entry;
}

void increase_accessed (struct cache_hash_entry* entry)
{
    int temp = (int)(entry->sector_info & ACCESSED_BITS);
    if (temp==63) return;
    entry->sector_info = (entry->sector_info & DIRTY_BIT) | (entry->sector_info & META_BIT) | 
                            ((temp+1) & ACCESSED_BITS);
}

void decrease_accessed (struct cache_hash_entry* entry)
{
    int temp = (int)(entry->sector_info & ACCESSED_BITS);
    if (temp==0) return;
    entry->sector_info = (entry->sector_info & DIRTY_BIT) | (entry->sector_info & META_BIT) | 
                         ((temp-1) & ACCESSED_BITS);  
}

void filesys_cache_write(disk_sector_t sector, const void *src, off_t offset, off_t size)
{
  ASSERT(offset + size <= DISK_SECTOR_SIZE);
  struct cache_hash_entry* entry;
  bool is_new_entry = look_and_lock(sector,&entry);
  
  if (!is_new_entry){
    entry->sector_info |=DIRTY_BIT ;
    lock_acquire(&flush_thread_lock); 
    if (!flush_thread_alive){
        flush_thread_alive=true;
	      lock_release(&flush_thread_lock);
        thread_create ("sleeping_beauty", PRI_DEFAULT - 1, sleep_and_flush, NULL);
    } else lock_release(&flush_thread_lock);     
  }
  
  if(is_new_entry && size!=DISK_SECTOR_SIZE) {
    num_misses++; 
    disk_read(filesys_disk, sector, entry->sector_data);
  }
  copy_and_unlock (entry, entry->sector_data + offset, src, size);

}

static void
sleep_and_flush(void *aux UNUSED)
{
   timer_msleep(FLUSH_SLEEP_SECONDS * 1000);
   filesys_flush_cache();
   lock_acquire(&flush_thread_lock);
   flush_thread_alive = false;
   lock_release(&flush_thread_lock);
}


//this function is inside a global lock right now
struct cache_hash_entry *
setup_cache_entry(disk_sector_t sector)
{
  ASSERT(lookup_cache_entry(sector)==NULL);
  ASSERT(hash_size(&cache_hash)<=(unsigned) MAX_ENTRIES); 

  while(cache_allowed_entries <= 0) /* okay, we're in some trouble. sleep until we can do something */
  {
    lock_release(&cache_hash_lock);
    timer_msleep(CACHE_ZERO_SLEEP_MSECONDS);
    lock_acquire(&cache_hash_lock);
  }

  if (hash_size(&cache_hash) >= cache_allowed_entries)
    cache_out(); 
  
  struct cache_hash_entry *
    entry = (struct cache_hash_entry *)malloc(sizeof(struct cache_hash_entry));
  entry->sector = sector;
  lock_init(&entry->sector_lock);
  entry->sector_data = malloc(DISK_SECTOR_SIZE);
  ASSERT(entry->sector_data!=NULL);
  entry->sector_info = INIT_NUM_ACCESSED;
  entry->ref_count = 0;
  entry->is_removed = false;
  hash_insert(&cache_hash, &entry->h_elem);
  return entry;
}

//TODO: go over this function
void cache_out()
{
  struct hash_iterator hash_iter;
  struct cache_hash_entry *best_evict, *temp_entry;
  int temp_score;
  int best_score = MAX_SCORE; //impossible score
  num_evictions++;
  
  hash_first(&hash_iter,&cache_hash);
  while (hash_next(&hash_iter)!=NULL){
    temp_entry=hash_entry(hash_cur(&hash_iter),struct cache_hash_entry,h_elem); 
    if((temp_score=evict_score(temp_entry)) < best_score){ 
        best_evict = temp_entry;
        best_score = temp_score;
    }
    decrease_accessed(temp_entry);
  }
  
  lock_acquire(&prefetch_list_lock);
  bitmap_set (prefetch_list,(size_t)best_evict->sector,false);
  lock_release(&prefetch_list_lock);
  hash_delete(&cache_hash, &best_evict->h_elem);
  
  /* check if this is accessed. if not, just remove it now */
  if(best_evict->ref_count == 0)
  {
    disk_write(filesys_disk, best_evict->sector, best_evict->sector_data); 
    free(best_evict->sector_data);
    free(best_evict);
  }
  else
  {  
    /* this entry will be evicted. until it is freed in memory, don't
     * allow additional entries in the hash (to preserve hash size limit) */
    cache_allowed_entries--;
  
    /*struct sector_to_evict *evictee = 
      (struct sector_to_evict*) malloc (sizeof(struct sector_to_evict));
    evictee->evictee = best_evict;
    lock_acquire(&eviction_list_lock);
    list_push_front(&eviction_list, &evictee->elem);
    lock_release (&eviction_list_lock);*/
    best_evict->is_removed = true;
  }
}

/* Will return 0 or negative numbers
 * The greater the number (i.e. closer to 0), the better is
 * the candidate in question for eviction */
static int
evict_score(const struct cache_hash_entry* entry)
{
   int acc_score = (int)(entry->sector_info & ACCESSED_BITS) * ACCESSED_WEIGHT;
   int dirty_score = (int)((entry->sector_info & DIRTY_BIT)>>7) * DIRTY_WEIGHT;
   int meta_score = (int)((entry->sector_info & META_BIT)>>6) * META_WEIGHT;
   return (acc_score+dirty_score+meta_score);
}

//debugging function
void print_sector_info(char *str, const struct cache_hash_entry *entry)
{
   int acc_score = (int)(entry->sector_info & ACCESSED_BITS);
   int dirty_score = (int)((entry->sector_info & DIRTY_BIT)>>7);
   int meta_score = (int)((entry->sector_info & META_BIT)>>6);
   printf("%s %s Sector:%d ACCESSED: %d DIRTY: %d META: %d \n",thread_current()->name,  str,entry->sector, acc_score,dirty_score,meta_score);
}

static unsigned
cache_hash_fn(const struct hash_elem *e, void *aux UNUSED)
{
  struct cache_hash_entry *cache_entry = hash_entry (e, struct cache_hash_entry, h_elem);
  return (hash_bytes(&cache_entry->sector, sizeof(cache_entry->sector)));
}


static bool
cache_less(const struct hash_elem *a_,
        const struct hash_elem *b_,
        void *aux UNUSED)
{
  struct cache_hash_entry *a = hash_entry(a_, struct cache_hash_entry, h_elem);
  struct cache_hash_entry *b = hash_entry(b_, struct cache_hash_entry, h_elem);
  return (a->sector < b->sector);
}

//TODO: synch this function with more granular locks
// are you sure? when we're flushing the cache, there should be no
// other processes around. so don't need granularlity
void
filesys_flush_cache()
{
   struct hash_iterator hash_iter;
   struct cache_hash_entry *temp_entry;
   lock_acquire(&cache_hash_lock);
   hash_first(&hash_iter,&cache_hash);
   while (hash_next(&hash_iter)!=NULL){
      temp_entry=hash_entry(hash_cur(&hash_iter),struct cache_hash_entry,h_elem);
      temp_entry->sector_info &= ~DIRTY_BIT;
      disk_write(filesys_disk, temp_entry->sector,temp_entry->sector_data);
   }
   lock_release(&cache_hash_lock);
}

void 
print_cache_stats()
{
   printf("\n--------------------------------\n");
   printf("         Cache Statistics         \n");
   printf(  "--------------------------------\n");
   printf("Num Misses: %d\n", num_misses);
   printf("Num evictions: %d\n", num_evictions);
   printf("\n--------------------------------\n");
}


